import grp
import cryptography.hazmat.primitives.asymmetric.x25519
import cryptography.hazmat.primitives.hmac
import cryptography.hazmat.primitives.ciphers.aead
import cryptography.utils
from concurrent import futures
import logging
import grpc
from proto import messages_pb2_grpc
from proto import messages_pb2 as messages

from enum import Enum


class State(Enum):
    INIT = 0
    HANDSHAKE_PART = 1
    HANDSHAKE_FINSHED = 2

ERROR_DETAIL = "State automata out of sync with protocol state"

class Server(messages_pb2_grpc.ServerServicer):

    def __init__(self):
        self.state = State.INIT
        #super().__init__()

    def InitiateHandshake(self, req, ctx: grpc.ServicerContext):
        if self.state != State.INIT:
            ctx.abort(grpc.StatusCode.PERMISSION_DENIED,details=ERROR_DETAIL)

        somebytes = bytes([0, 255])

        serverHello = messages.ServerHello(
            nonce=somebytes,
            key_share=somebytes,
        )

        return serverHello

    def Integrity(self, req, ctx):
        if self.state != State.HANDSHAKE_PART:
            ctx.abort(grpc.StatusCode.PERMISSION_DENIED,details=ERROR_DETAIL)

        somebytes = bytes([0, 255])

        verifyClientHandshake = messages.VerifyIntegrity(
            nonce=somebytes,
            key_share=somebytes,
        )

        return verifyClientHandshake

    def TransferData(self, req, ctx):
        if self.state != State.HANDSHAKE_FINSHED:
            ctx.abort(grpc.StatusCode.PERMISSION_DENIED,details=ERROR_DETAIL)

        status = messages.Status(
            message="We did it",
            state=messages.Status.OK
        )

        return status


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
