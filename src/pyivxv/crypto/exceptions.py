class VerificationError(Exception):
    def __init__(self, failed_components: list[str]):
        self.failed_components = failed_components
        super().__init__(f"Verification failed at: {', '.join(failed_components)}")
