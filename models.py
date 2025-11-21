from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from datetime import datetime

db = SQLAlchemy()


# ======================
# Usuários do sistema
# ======================
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(50), default="consulta")  # admin, estoquista, consulta
    ativo = db.Column(db.Boolean, default=True)  # bloquear usuário sem excluir

    def is_active(self):
        return self.ativo


# ======================
# Seções de materiais
# ======================
class Secao(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nome = db.Column(db.String(150), unique=True, nullable=False)
    descricao = db.Column(db.String(300))


# ======================
# Produtos
# ======================
class Produto(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nome = db.Column(db.String(150), nullable=False)
    quantidade = db.Column(db.Integer, default=0)

    # 👇 ADICIONE ESTA LINHA
    unidade = db.Column(db.String(10), default=None)

    secao_id = db.Column(db.Integer, db.ForeignKey("secao.id"))
    foto = db.Column(db.String(300))  # caminho da imagem
    secao = db.relationship("Secao")



# ======================
# Registro de retiradas
# ======================
class Retirada(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    produto_id = db.Column(db.Integer, db.ForeignKey("produto.id"))
    usuario = db.Column(db.String(120))
    quantidade = db.Column(db.Integer)
    data = db.Column(db.DateTime, default=datetime.utcnow)
    observacao = db.Column(db.String(300))
    produto = db.relationship("Produto")


# ======================
# Log de Auditoria
# ======================
class LogAcao(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    usuario = db.Column(db.String(120))
    acao = db.Column(db.String(300))
    data = db.Column(db.DateTime, default=datetime.utcnow)
