

class HandlerBase:
    def __init__(self, **overrides) -> None:
        for k, v in overrides:
            setattr(self, k, v)