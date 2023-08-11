import angr

class FunStackState(angr.SimStatePlugin):
    def __init__(self,
                 chain, chain_addr, chain_loop_func):
        super().__init__()
        self.chain = chain    
        self.chain_addr = chain_addr
        self.chain_loop_func = chain_loop_func

    @angr.SimStatePlugin.memo
    def copy(self, memo):
        return FunStackState(self.chain, self.chain_addr, self.chain_loop_func)






























































