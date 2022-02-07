class DcomException(Exception):
    pass


class WbemStopIteration(Exception):
    pass


class RpcException(Exception):
    def __init__(self, msg, code):
        msg = f'{msg} ({code})'
        super().__init__(msg)


class WbemException(Exception):
    def __init__(self, msg, code):
        msg = f'{msg} ({code})'
        super().__init__(msg)
