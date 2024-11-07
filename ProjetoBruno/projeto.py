import hashlib
from pymongo.mongo_client import MongoClient
from bcrypt import hashpw, gensalt, checkpw
from cryptography.fernet import Fernet
import ttkbootstrap as ttk
from ttkbootstrap.constants import *
from tkinter import messagebox, simpledialog

# Funções para criptografia
def gerar_chave_criptografia():
    return Fernet.generate_key()

chave_secreta = gerar_chave_criptografia()
cipher_suite = Fernet(chave_secreta)

mongo_client = MongoClient("mongodb+srv://nicolas:WnQwltP8P1dUj3CG@cluster0.bdeme.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0") 
db = mongo_client["Hospital"]

# Funções de Criptografia
def criptografar(texto):
    return cipher_suite.encrypt(texto.encode()).decode()

def descriptografar(texto_criptografado):
    return cipher_suite.decrypt(texto_criptografado.encode()).decode()

# Funções do banco de dados e autenticação
def adicionar_paciente():
    id_paciente = simpledialog.askstring("ID do Paciente", "Informe o ID do paciente:")
    nome_paciente = criptografar(simpledialog.askstring("Nome", "Informe o nome do paciente:"))
    idade_paciente = criptografar(simpledialog.askstring("Idade", "Informe a idade do paciente:"))
    historico_paciente = criptografar(simpledialog.askstring("Histórico", "Informe o histórico médico:"))

    colecao_pacientes = db["Pacientes"]
    colecao_pacientes.insert_one({
        "Identificacao": id_paciente,
        "Nome": nome_paciente,
        "Idade": idade_paciente,
        "Historico": historico_paciente,
    })

    messagebox.showinfo("Sucesso", "Paciente adicionado com sucesso!")

def autenticar_usuario():
    id_medico = simpledialog.askstring("Identificação do Médico", "Informe a identificação do médico:")
    senha = simpledialog.askstring("Senha", "Informe a senha:", show="*").encode('utf-8')

    colecao_medicos = db["Medicos"]
    medico = colecao_medicos.find_one({"IdentificacaoMedica": id_medico})

    if medico and checkpw(senha, medico['Senha']):
        messagebox.showinfo("Sucesso", "Autenticação realizada com sucesso.")
        return True
    else:
        messagebox.showerror("Erro", "Médico não encontrado ou senha incorreta.")
        return False

def verificar_2fa():
    codigo_correto = "876234"
    codigo_usuario = simpledialog.askstring("2FA", "Digite o código de 2FA:")

    if codigo_usuario == codigo_correto:
        messagebox.showinfo("Sucesso", "Código 2FA verificado.")
        return True
    else:
        messagebox.showerror("Erro", "Código 2FA incorreto.")
        return False

def visualizar_paciente():
    if not autenticar_usuario() or not verificar_2fa():
        return

    id_paciente = simpledialog.askstring("ID do Paciente", "Informe a identificação do paciente:")
    colecao_pacientes = db["Pacientes"]
    consulta = colecao_pacientes.find({"Identificacao": id_paciente})

    for paciente in consulta:
        try:
            nome = descriptografar(paciente.get('Nome', ''))
            idade = descriptografar(paciente.get('Idade', ''))
            historico = descriptografar(paciente.get('Historico', ''))

            info_paciente = f"Nome: {nome}\nIdade: {idade}\nHistórico: {historico}"
            messagebox.showinfo("Informações do Paciente", info_paciente)

        except Exception:
            messagebox.showerror("Erro", "Chave de acesso expirada, não foi possível acessar os dados.")
            return

def adicionar_medico():
    id_medico = simpledialog.askstring("ID do Médico", "Informe a identificação do médico:")
    nome_medico = criptografar(simpledialog.askstring("Nome", "Informe o nome do médico:"))
    especialidade_medico = criptografar(simpledialog.askstring("Especialidade", "Informe a especialidade do médico:"))
    senha_medico = simpledialog.askstring("Senha", "Informe uma senha para o médico:", show="*").encode('utf-8')
    senha_criptografada = hashpw(senha_medico, gensalt())

    colecao_medicos = db["Medicos"]
    colecao_medicos.insert_one({
        "IdentificacaoMedica": id_medico,
        "Nome": nome_medico,
        "Especialidade": especialidade_medico,
        "Senha": senha_criptografada
    })

    messagebox.showinfo("Sucesso", "Médico cadastrado com sucesso!")

# Interface gráfica com ttkbootstrap
app = ttk.Window(themename="cosmo")
app.title("Sistema de Gestão Hospitalar")
app.geometry("500x400")

# Título principal
title_label = ttk.Label(app, text="Sistema de Gestão Hospitalar", font=("Helvetica", 18, "bold"))
title_label.pack(pady=20)

# Botões com estilo moderno
btn_ver_paciente = ttk.Button(app, text="Ver Paciente", command=visualizar_paciente, bootstyle=PRIMARY)
btn_ver_paciente.pack(pady=10, fill=X, padx=20)

btn_inserir_paciente = ttk.Button(app, text="Inserir Paciente", command=adicionar_paciente, bootstyle=SUCCESS)
btn_inserir_paciente.pack(pady=10, fill=X, padx=20)

btn_inserir_medico = ttk.Button(app, text="Inserir Médico", command=adicionar_medico, bootstyle=INFO)
btn_inserir_medico.pack(pady=10, fill=X, padx=20)

# Executa a interface gráfica
app.mainloop()
