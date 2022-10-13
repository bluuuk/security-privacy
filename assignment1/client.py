import grpc
import logging
from proto import messages_pb2_grpc
from proto import messages_pb2 as messages


def run():
    # NOTE(gRPC Python Team): .close() is possible on a channel and should be
    # used in circumstances in which the with statement does not fit the needs
    # of the code.
    with grpc.insecure_channel('localhost:50051') as channel:
        stub = messages_pb2_grpc.ServerStub(channel)

        somebytes = bytes([0, 255])

        clientHello = messages.ClientHello(
            nonce=somebytes,
            key_share=somebytes,
            share_signature=somebytes
        )

        serverHello = stub.InitiateHandshake(clientHello)

        verifyServerHandshake = messages.VerifyIntegrity(
            integrity=somebytes
        )

        verifyClientHandshake = stub.Integrity(verifyServerHandshake)

        encryptedData = messages.EncryptedData(
            iv=somebytes,
            encrypted=somebytes,
            integrity=somebytes,
        )

        status = stub.TransferData(encryptedData)


if __name__ == '__main__':
    logging.basicConfig()
    run()
