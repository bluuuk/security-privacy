import grpc
import logging
from proto import messages_pb2_grpc, messages_pb2


def run():
    # NOTE(gRPC Python Team): .close() is possible on a channel and should be
    # used in circumstances in which the with statement does not fit the needs
    # of the code.
    with grpc.insecure_channel('localhost:50051') as channel:
        stub = messages_pb2_grpc.ServerStub(channel)
        stub.Integrity(messages_pb2.VerifyIntegrity())


if __name__ == '__main__':
    logging.basicConfig()
    run()
