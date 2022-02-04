class RpcException(Exception):
    def __init__(self, msg, code):
        msg = f'{msg} ({code})'
        super().__init__(msg)
