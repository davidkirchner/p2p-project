

class HandlerBase:
    def __init__(self, **overrides) -> None:
        for k, v in overrides.items():
            setattr(self, k, v)