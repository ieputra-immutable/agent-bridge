//! Milestone 0 experiment. No listener is added to the production broker.
use agent_bridge::protocol::MAX_FRAME;
use futures::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, StreamExt, io::Cursor};
use libp2p::{
    PeerId, StreamProtocol, Swarm, SwarmBuilder,
    request_response::{self, Codec, ProtocolSupport},
    swarm::{SwarmEvent, dial_opts::DialOpts},
};
use std::{io, time::Duration};

const PROTOCOL: StreamProtocol = StreamProtocol::new("/agent-bridge/probe/1");

#[derive(Clone, Default)]
struct BoundedCodec;

async fn read_frame<T: AsyncRead + Unpin>(io: &mut T) -> io::Result<Vec<u8>> {
    let mut header = [0; 4];
    io.read_exact(&mut header).await?;
    let length = u32::from_be_bytes(header) as usize;
    if length > MAX_FRAME {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "frame too large",
        ));
    }
    let mut body = vec![0; length];
    io.read_exact(&mut body).await?;
    Ok(body)
}

async fn write_frame<T: AsyncWrite + Unpin>(io: &mut T, body: Vec<u8>) -> io::Result<()> {
    if body.len() > MAX_FRAME {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "frame too large",
        ));
    }
    io.write_all(&(body.len() as u32).to_be_bytes()).await?;
    io.write_all(&body).await?;
    io.close().await
}

impl Codec for BoundedCodec {
    type Protocol = StreamProtocol;
    type Request = Vec<u8>;
    type Response = Vec<u8>;

    async fn read_request<T: AsyncRead + Unpin + Send>(
        &mut self,
        _: &StreamProtocol,
        io: &mut T,
    ) -> io::Result<Vec<u8>> {
        read_frame(io).await
    }

    async fn read_response<T: AsyncRead + Unpin + Send>(
        &mut self,
        _: &StreamProtocol,
        io: &mut T,
    ) -> io::Result<Vec<u8>> {
        read_frame(io).await
    }

    async fn write_request<T: AsyncWrite + Unpin + Send>(
        &mut self,
        _: &StreamProtocol,
        io: &mut T,
        body: Vec<u8>,
    ) -> io::Result<()> {
        write_frame(io, body).await
    }

    async fn write_response<T: AsyncWrite + Unpin + Send>(
        &mut self,
        _: &StreamProtocol,
        io: &mut T,
        body: Vec<u8>,
    ) -> io::Result<()> {
        write_frame(io, body).await
    }
}

fn peer() -> Swarm<request_response::Behaviour<BoundedCodec>> {
    SwarmBuilder::with_new_identity()
        .with_tokio()
        .with_quic()
        .with_behaviour(|_| {
            request_response::Behaviour::with_codec(
                BoundedCodec,
                [(PROTOCOL, ProtocolSupport::Full)],
                request_response::Config::default()
                    .with_request_timeout(Duration::from_secs(3))
                    .with_max_concurrent_streams(4),
            )
        })
        .unwrap()
        .build()
}

async fn listen(swarm: &mut Swarm<request_response::Behaviour<BoundedCodec>>) -> libp2p::Multiaddr {
    swarm
        .listen_on("/ip4/127.0.0.1/udp/0/quic-v1".parse().unwrap())
        .unwrap();
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if let SwarmEvent::NewListenAddr { address, .. } = swarm.select_next_some().await {
                return address;
            }
        }
    })
    .await
    .expect("listener did not start")
}

#[tokio::test]
async fn authenticated_quic_peers_exchange_bounded_frames() {
    let mut alice = peer();
    let mut bob = peer();
    let alice_id = *alice.local_peer_id();
    let bob_id = *bob.local_peer_id();
    let address = listen(&mut bob).await;
    alice
        .dial(DialOpts::peer_id(bob_id).addresses(vec![address]).build())
        .unwrap();
    // Exercise the full permitted frame size over a real encrypted loopback connection.
    let payload = vec![42; MAX_FRAME];
    let mut request = None;
    let mut bob_authenticated = false;
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            tokio::select! {
                event = alice.select_next_some() => match event {
                    SwarmEvent::ConnectionEstablished { peer_id, .. } => {
                        assert_eq!(peer_id, bob_id);
                        request = Some(alice.behaviour_mut().send_request(&bob_id, payload.clone()));
                    }
                    SwarmEvent::Behaviour(request_response::Event::Message {
                        peer, message: request_response::Message::Response { request_id, response }, ..
                    }) => {
                        assert_eq!(peer, bob_id);
                        assert_eq!(Some(request_id), request);
                        assert_eq!(response, payload);
                        assert!(bob_authenticated);
                        break;
                    }
                    SwarmEvent::Behaviour(request_response::Event::OutboundFailure { error, .. }) => panic!("request failed: {error}"),
                    SwarmEvent::OutgoingConnectionError { error, .. } => panic!("dial failed: {error}"),
                    _ => {}
                },
                event = bob.select_next_some() => match event {
                    SwarmEvent::ConnectionEstablished { peer_id, .. } => {
                        assert_eq!(peer_id, alice_id);
                        bob_authenticated = true;
                    }
                    SwarmEvent::Behaviour(request_response::Event::Message {
                        peer, message: request_response::Message::Request { request, channel, .. }, ..
                    }) => {
                        assert_eq!(peer, alice_id);
                        assert_eq!(request, payload);
                        bob.behaviour_mut().send_response(channel, request).unwrap();
                    }
                    SwarmEvent::Behaviour(request_response::Event::InboundFailure { error, .. }) => panic!("receive failed: {error}"),
                    _ => {}
                }
            }
        }
    }).await.expect("exchange timed out");
}

#[tokio::test]
async fn dial_rejects_a_different_peer_identity() {
    let mut alice = peer();
    let mut bob = peer();
    let address = listen(&mut bob).await;
    let wrong_id = PeerId::random();
    alice
        .dial(DialOpts::peer_id(wrong_id).addresses(vec![address]).build())
        .unwrap();
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            tokio::select! {
                event = alice.select_next_some() => match event {
                    SwarmEvent::OutgoingConnectionError { peer_id, error, .. } => {
                        assert_eq!(peer_id, Some(wrong_id));
                        assert!(matches!(error, libp2p::swarm::DialError::WrongPeerId { .. }), "{error:?}");
                        break;
                    }
                    SwarmEvent::ConnectionEstablished { .. } => panic!("wrong identity accepted"),
                    _ => {}
                },
                _ = bob.select_next_some() => {}
            }
        }
    }).await.expect("identity rejection timed out");
}

#[tokio::test]
async fn codec_rejects_oversized_and_truncated_frames() {
    let mut oversized = Cursor::new(((MAX_FRAME + 1) as u32).to_be_bytes());
    assert_eq!(
        read_frame(&mut oversized).await.unwrap_err().kind(),
        io::ErrorKind::InvalidData
    );
    let mut truncated = Cursor::new(vec![0, 0, 0, 2, 1]);
    assert_eq!(
        read_frame(&mut truncated).await.unwrap_err().kind(),
        io::ErrorKind::UnexpectedEof
    );
    let mut short_header = Cursor::new(vec![0, 0]);
    assert_eq!(
        read_frame(&mut short_header).await.unwrap_err().kind(),
        io::ErrorKind::UnexpectedEof
    );
    let mut output = Cursor::new(Vec::new());
    assert_eq!(
        write_frame(&mut output, vec![0; MAX_FRAME + 1])
            .await
            .unwrap_err()
            .kind(),
        io::ErrorKind::InvalidInput
    );
    assert!(output.into_inner().is_empty());
}
