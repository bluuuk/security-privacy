import grpc
import logging
from crypto import CryptoHandshakeContainer
from proto import messages_pb2_grpc
from proto import messages_pb2 as messages

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import Encoding,PublicFormat
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey

with open("./client/private.pem","rb") as f:
    PRIVATE_KEY = serialization.load_pem_private_key(f.read(),password=None)

def run():
    # NOTE(gRPC Python Team): .close() is possible on a channel and should be
    # used in circumstances in which the with statement does not fit the needs
    # of the code.
    with grpc.insecure_channel('localhost:50051') as channel:
        stub = messages_pb2_grpc.ServerStub(channel)

        cryptobox = CryptoHandshakeContainer()
        key_share,nonce = cryptobox.key_share_init()
        signature = cryptobox.create_key_share_signature(PRIVATE_KEY)

        clientHello = messages.ClientHello(
            nonce=nonce,
            key_share=key_share.public_bytes(Encoding.Raw,PublicFormat.Raw),
            share_signature=signature
        )

        serverHello = stub.InitiateHandshake(clientHello)
        cryptobox.finish_key_share(X25519PublicKey.from_public_bytes(serverHello.key_share),serverHello.nonce)
        
        verifyServerHandshake = messages.VerifyIntegrity(
            integrity=cryptobox.create_integrity(serverHello.SerializeToString())
        )

        verifyClientHandshake = stub.Integrity(verifyServerHandshake)

        if not cryptobox.check_integrity(clientHello.SerializeToString(),verifyClientHandshake.integrity):
            channel.close()

        with open("./client/data.csv","rb") as f:
            nonce,data = cryptobox.encrypt(f.read())

        encryptedData = messages.EncryptedData(
            nonce=nonce,
            encrypted=data,
        )

        status = stub.TransferData(encryptedData)


if __name__ == '__main__':
    logging.basicConfig()
    run()
