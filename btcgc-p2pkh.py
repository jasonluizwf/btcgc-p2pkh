import ecdsa
import hashlib
import base58
from requests import get
import tkinter as tk
from tkinter import ttk, scrolledtext
import threading

class AplicacaoGeradoraCarteiraBitcoin:
    def __init__(self, root):
        self.root = root
        self.root.title("Gerador de Carteira Bitcoin")
        self.root.geometry("500x400")

        self.notebook = ttk.Notebook(root)

        # Aba 1: Gerar Carteira
        self.aba_gerar = ttk.Frame(self.notebook)
        self.notebook.add(self.aba_gerar, text="Gerar Carteira")

        self.botao_gerar = tk.Button(self.aba_gerar, text="Gerar Carteira", command=self.gerar_carteira)
        self.botao_gerar.pack(pady=20)

        self.rotulo_chave_privada = tk.Label(self.aba_gerar, text="Chave Privada:")
        self.rotulo_chave_privada.pack()

        self.entrada_chave_privada = tk.Entry(self.aba_gerar, state="readonly", width=40, font=("Helvetica", 10))
        self.entrada_chave_privada.pack(pady=5, padx=10)

        self.rotulo_endereco = tk.Label(self.aba_gerar, text="Endereço Bitcoin:")
        self.rotulo_endereco.pack()

        self.entrada_endereco = tk.Entry(self.aba_gerar, state="readonly", width=40, font=("Helvetica", 10))
        self.entrada_endereco.pack(pady=5, padx=10)

        # Adicionando a variável de controle para o tipo de carteira
        self.variavel_tipo_carteira = tk.StringVar()
        self.variavel_tipo_carteira.set("p2pkh")

        # Aba 2: Gerar e Verificar Carteira
        self.aba_gerar_verificar = ttk.Frame(self.notebook)
        self.notebook.add(self.aba_gerar_verificar, text="Gerar e Verificar Carteira")

        self.botao_iniciar = tk.Button(self.aba_gerar_verificar, text="Iniciar", command=self.iniciar_geracao)
        self.botao_iniciar.pack(side=tk.LEFT, padx=5)

        self.botao_parar = tk.Button(self.aba_gerar_verificar, text="Parar", command=self.parar_geracao)
        self.botao_parar.pack(side=tk.LEFT, padx=5)
        self.botao_parar["state"] = "disabled"

        self.rotulo_contador = tk.Label(self.aba_gerar_verificar, text="Carteiras Analisadas: 0")
        self.rotulo_contador.pack(pady=10)

        self.area_log = scrolledtext.ScrolledText(self.aba_gerar_verificar, width=50, height=10, state="disabled", font=("Helvetica", 10))
        self.area_log.pack(pady=10)

        self.notebook.pack()

        # Variáveis de controle
        self.carteiras_analisadas = 0

    def gerar_carteira(self):
        endereco, chave_privada, _, wif_chave_privada = self._gerar_carteira()
        self.entrada_chave_privada.config(state="normal")
        self.entrada_endereco.config(state="normal")

        self.entrada_chave_privada.delete(0, tk.END)
        self.entrada_chave_privada.insert(0, wif_chave_privada)

        self.entrada_endereco.delete(0, tk.END)
        self.entrada_endereco.insert(0, endereco)

        self.entrada_chave_privada.config(state="readonly")
        self.entrada_endereco.config(state="readonly")

    def gerar_verificar_carteira(self):
        try:
            endereco, chave_privada, chave_publica, wif_chave_privada = self._gerar_carteira()
            saldo_txo_fundado = self._obter_saldo_txo_fundado(endereco)

            if saldo_txo_fundado > 0:
                self.salvar_saldo_em_arquivo(endereco, chave_privada, chave_publica, saldo_txo_fundado)

            texto_log = f"Endereço Bitcoin: {endereco}\nChave Privada (WIF): {wif_chave_privada}\nSaldo: {saldo_txo_fundado}\n"
            self._atualizar_log(texto_log)

            self.carteiras_analisadas += 1
            self.rotulo_contador.config(text=f"Carteiras Analisadas: {self.carteiras_analisadas}")
        except Exception as e:
            self._atualizar_log(f"Erro durante a geração e verificação da carteira: {str(e)}\n")

    def salvar_saldo_em_arquivo(self, endereco, chave_privada, chave_publica, saldo):
        with open("saldo_positivo.txt", "a") as arquivo:
            arquivo.write(f"Endereço: {endereco}\nChave Privada: {chave_privada}\nChave Pública: {chave_publica}\nSaldo: {saldo}\n\n")

    def _gerar_carteira(self):
        private_key = ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1)
        public_key = private_key.get_verifying_key().to_string()

        sha256_hash = hashlib.sha256(public_key).digest()
        ripemd160_hash = hashlib.new('ripemd160')
        ripemd160_hash.update(sha256_hash)
        public_key_hash = ripemd160_hash.digest()

        if self.variavel_tipo_carteira.get() == "p2pkh":
            extended_hash = b'\x00' + public_key_hash
        else:
            # Lidar com outros tipos de carteira
            pass

        checksum = hashlib.sha256(hashlib.sha256(extended_hash).digest()).digest()[:4]
        extended_hash += checksum

        wif_chave_privada = base58.b58encode_check(b'\x80' + private_key.to_string()).decode('utf-8')

        endereco = base58.b58encode(extended_hash).decode('utf-8')
        chave_privada_hex = private_key.to_string().hex()
        chave_publica_hex = public_key.hex()

        return endereco, chave_privada_hex, chave_publica_hex, wif_chave_privada

    def _obter_saldo_txo_fundado(self, endereco):
        try:
            resposta = get(f"https://mempool.space/api/endereco/{endereco}")

            if resposta.status_code == 200:
                dados_api = resposta.json()
                saldo_txo_fundado = dados_api.get('estatisticas_chain', {}).get('saldo_txo_fundado', 0)
                return saldo_txo_fundado
            else:
                return 0
        except Exception as e:
            return 0

    def _atualizar_log(self, texto):
        self.area_log.config(state="normal")
        self.area_log.insert(tk.END, texto)
        self.area_log.see(tk.END)
        self.area_log.config(state="disabled")

    def _limpar_log(self):
        self.area_log.config(state="normal")
        self.area_log.delete(1.0, tk.END)
        self.area_log.config(state="disabled")

    def iniciar_geracao(self):
        self.botao_parar["state"] = "normal"
        self.botao_iniciar["state"] = "disabled"
        self._limpar_log()
        self.parar_thread = False
        self.thread = threading.Thread(target=self._gerar_verificar_carteira_continuamente)
        self.thread.start()

    def parar_geracao(self):
        self.parar_thread = True
        self.botao_iniciar["state"] = "normal"
        self.botao_parar["state"] = "disabled"

    def _gerar_verificar_carteira_continuamente(self):
        while not self.parar_thread:
            self.gerar_verificar_carteira()

if __name__ == "__main__":
    root = tk.Tk()
    app = AplicacaoGeradoraCarteiraBitcoin(root)
    root.mainloop()
