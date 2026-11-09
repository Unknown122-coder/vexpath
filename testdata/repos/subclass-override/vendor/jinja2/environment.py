"""Template environment."""


class Environment:
    def __init__(self, autoescape=False, **kwargs):
        self.autoescape = autoescape
