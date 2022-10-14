from concurrent import futures
import logging
from enum import Enum

import grpc
from crypto import CryptoHandshakeContainer
from proto import messages_pb2_grpc
from proto import messages_pb2 as messages

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import Encoding,PublicFormat
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey


class State(Enum):
    INIT = 0
    HANDSHAKE_PART = 1
    HANDSHAKE_FINSHED = 2

ERROR_DETAIL = "State automata out of sync with protocol state"

with open("./server/public.pem","rb") as f:
    PUBLIC_KEY = serialization.load_pem_public_key(f.read())


class Server(messages_pb2_grpc.ServerServicer):

    def __init__(self):
        self.state = State.INIT
        self.cryptobox = None
        self.client_hello = None
        self.server_hello = None
        #super().__init__()

    def InitiateHandshake(self, req : messages.ClientHello, ctx: grpc.ServicerContext):
        
        if self.state != State.INIT:
            ctx.abort(grpc.StatusCode.PERMISSION_DENIED,details=ERROR_DETAIL)

        self.cryptobox = CryptoHandshakeContainer()
        key_share,nonce = self.cryptobox.key_share_init()

        serverHello = messages.ServerHello(
            nonce=nonce,
            key_share=key_share.public_bytes(Encoding.Raw,PublicFormat.Raw),
        )

        self.client_hello = req.SerializeToString()
        self.server_hello = serverHello.SerializeToString()

        self.cryptobox.finish_key_share(
            X25519PublicKey.from_public_bytes(req.key_share),
            req.nonce
        )

        self.state = State.HANDSHAKE_PART
        return serverHello

    def Integrity(self, req : messages.VerifyIntegrity, ctx):
        if self.state != State.HANDSHAKE_PART:
            ctx.abort(grpc.StatusCode.PERMISSION_DENIED,details=ERROR_DETAIL)

        verifyClientHandshake = messages.VerifyIntegrity(
            integrity=self.cryptobox.create_integrity(self.client_hello)
        )

        if not self.cryptobox.check_integrity(self.server_hello,req.integrity):
            ctx.abort(grpc.StatusCode.PERMISSION_DENIED,details=ERROR_DETAIL)

        self.state = State.HANDSHAKE_FINSHED
        return verifyClientHandshake

    def TransferData(self, req : messages.EncryptedData, ctx):
        if self.state != State.HANDSHAKE_FINSHED:
            ctx.abort(grpc.StatusCode.PERMISSION_DENIED,details=ERROR_DETAIL)

        with open("./server/data.csv","wb") as f:
            f.write(
                self.cryptobox.decrypt(req.nonce,req.encrypted)
            )

        return messages.Status(message="Yes",state=messages.Status.OK)


def serve():
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=2))
    messages_pb2_grpc.add_ServerServicer_to_server(
        Server(), server
    )
    server.add_insecure_port('[::]:50051')
    server.start()
    server.wait_for_termination()


if __name__ == '__main__':
    logging.basicConfig()
    serve()
