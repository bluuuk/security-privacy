import cryptography.hazmat.primitives.asymmetric.x25519
import cryptography.hazmat.primitives.hmac
import cryptography.hazmat.primitives.ciphers.aead
import cryptography.utils
from concurrent import futures
import logging
import grpc
from proto import messages_pb2_grpc


class Server(messages_pb2_grpc.ServerServicer):

    def InitiateHandshake(self, req, ctx):
        pass

    def Integrity(self, req, ctx):
        pass

    def TransferData(self, req, ctx):
        pass


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
