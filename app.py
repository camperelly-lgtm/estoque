import os
from datetime import datetime
from flask import Flask, render_template, redirect, url_for, request, flash, session, send_file
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from dotenv import load_dotenv
from sqlalchemy import func
import requests
import fitz  # PyMuPDF para ler PDF
import xmltodict
from collections import defaultdict
from fuzzywuzzy import fuzz
import PyPDF2
import re
import pandas as pd

# ============================================
#   CONFIGURAÇÃO FLASK E BANCO
# ============================================
load_dotenv()
app = Flask(__name__)
app.secret_key = "SEGREDO_SEGURO_AQUI"
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///estoque.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)
UPLOAD_FOLDER = "static/img/itens"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# ============================================
#   LOGIN MANAGER
# ============================================
login_manager = LoginManager()
login_manager.login_view = "login"
login_manager.init_app(app)

# ============================================
#   MODELS
# ============================================
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True)
    password = db.Column(db.String(255))
    role = db.Column(db.String(20), default="consulta")
    ativo = db.Column(db.Boolean, default=True)

    def is_authenticated(self): return True
    def is_active(self): return self.ativo
    def is_anonymous(self): return False
    def get_id(self): return str(self.id)

class Secao(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nome = db.Column(db.String(50))
    descricao = db.Column(db.String(200))

class Produto(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nome = db.Column(db.String(120))
    quantidade = db.Column(db.Integer, default=0)
    unidade = db.Column(db.String(10))   #  👈 ADICIONADO
    foto = db.Column(db.String(200))
    secao_id = db.Column(db.Integer, db.ForeignKey("secao.id"))
    secao = db.relationship("Secao")

class Retirada(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    produto_id = db.Column(db.Integer, db.ForeignKey("produto.id"))
    quantidade = db.Column(db.Integer)
    usuario = db.Column(db.String(80))
    observacao = db.Column(db.String(200))
    data = db.Column(db.DateTime, default=datetime.utcnow)
    produto = db.relationship("Produto")

class LogAcao(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    usuario = db.Column(db.String(80))
    acao = db.Column(db.String(255))
    data = db.Column(db.DateTime, default=datetime.utcnow)

class Movimentacao(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    data_hora = db.Column(db.String(19))  # DD/MM/AAAA HH:MM:SS
    produto = db.Column(db.String(120))
    secao = db.Column(db.String(120))
    entrada = db.Column(db.Integer, default=0)
    retirada = db.Column(db.Integer, default=0)
    estoque_atual = db.Column(db.Integer)
    usuario = db.Column(db.String(80))
    acao = db.Column(db.String(100))
    obs = db.Column(db.String(255))

# ============================================
#   FUNCÕES AUXILIARES (WHATSAPP / LOG / MOV)
# ============================================
WHATSAPP_TOKEN = os.getenv("WHATSAPP_TOKEN")
WHATSAPP_PHONE_ID = os.getenv("WHATSAPP_PHONE_ID")
WHATSAPP_DESTINO = os.getenv("WHATSAPP_DESTINO")

# ---------- CONFIGURAÇÕES DE EMAIL ----------
EMAIL_HOST = os.getenv("EMAIL_HOST")
EMAIL_PORT = int(os.getenv("EMAIL_PORT", 587))
EMAIL_USER = os.getenv("EMAIL_USER")
EMAIL_PASS = os.getenv("EMAIL_PASS")
EMAIL_DESTINO = os.getenv("EMAIL_DESTINO")

def enviar_whatsapp(mensagem: str):
    if not WHATSAPP_TOKEN or not WHATSAPP_PHONE_ID or not WHATSAPP_DESTINO:
        print("⚠ WhatsApp não configurado corretamente.")
        return
    url = f"https://graph.facebook.com/v19.0/{WHATSAPP_PHONE_ID}/messages"
    headers = {"Authorization": f"Bearer {WHATSAPP_TOKEN}", "Content-Type": "application/json"}
    payload = {"messaging_product": "whatsapp", "to": WHATSAPP_DESTINO, "type": "text", "text": {"body": mensagem}}
    requests.post(url, headers=headers, json=payload)

def registrar_log(usuario, acao, detalhes=""):
    log = LogAcao(usuario=usuario, acao=f"{acao} | {detalhes}", data=datetime.utcnow())
    db.session.add(log)
    db.session.commit()

def registrar_movimentacao(produto_obj, usuario, acao, entrada=0, retirada=0, obs=""):
    mov = Movimentacao(
        data_hora=datetime.now().strftime("%d/%m/%Y %H:%M:%S"),
        produto=produto_obj.nome,
        secao=produto_obj.secao.nome if produto_obj.secao else "Sem seção",
        entrada=entrada,
        retirada=retirada,
        estoque_atual=produto_obj.quantidade,
        usuario=usuario,
        acao=acao,
        obs=obs
    )
    db.session.add(mov)
    db.session.commit()

# -------------- EXTRA LISTA / ORDEM DE COMPRA PDF --------------
def extrair_itens_xml(caminho_xml):
    try:
        with open(caminho_xml, "rb") as f:
            dados = xmltodict.parse(f)
    except:
        return []

    # Tenta encontrar produtos independente da estrutura
    def localizar(d):
        try:
            return d["nfeProc"]["NFe"]["infNFe"]["det"]
        except:
            try:
                return d["NFe"]["infNFe"]["det"]
            except:
                return None

    det = localizar(dados)
    if not det:
        return []

    if isinstance(det, dict):
        det = [det]  # transforma único item em lista

    itens = []
    for item in det:
        p = item["prod"]
        nome = p["xProd"]
        qtd = float(p["qCom"])
        unidade = normalizar_unidade(p.get("uCom", ""))
        itens.append({
            "nome": nome,
            "qtd": int(qtd),
            "unidade": unidade
        })

    return itens

def extrair_itens_nf(caminho_pdf):
    doc = fitz.open(caminho_pdf)
    linhas = []
    for pagina in doc:
        texto = pagina.get_text("text")
        for l in texto.split("\n"):
            linhas.append(l.strip())
    doc.close()

    itens_nf = []
    gravando = False

    for linha in linhas:
        upper = linha.upper()

        if "DADOS DO PRODUTO" in upper and "SERVI" in upper:
            gravando = True
            continue

        if gravando and "FIM DOS PRODUTOS" in upper:
            break

        if gravando:
            partes = linha.split()
            if len(partes) < 5 or not partes[0].isnumeric():
                continue

            cod = partes[0]

            idx_ncm = None
            for i, p in enumerate(partes):
                if p.isdigit() and len(p) == 8:
                    idx_ncm = i
                    break

            if not idx_ncm or idx_ncm < 2:
                continue

            descricao = " ".join(partes[1:idx_ncm]).strip()

            qtd = None
            for p in partes[idx_ncm+1:]:
                if p.replace(",", "").isdigit():
                    qtd = int(p.replace(",", ""))
                else:
                    break

            if descricao and qtd:
                itens_nf.append({"nome": descricao, "qtd": qtd})

    agrupado = defaultdict(int)
    for item in itens_nf:
        agrupado[item["nome"]] += item["qtd"]

    return [{"nome": nome, "qtd": qtd} for nome, qtd in agrupado.items()]

def gerar_pdf_requisicao_selecionada(lista):
    from reportlab.pdfgen import canvas
    from reportlab.lib.pagesizes import A4

    caminho = os.path.join("static", "requisicao_compra.pdf")
    c = canvas.Canvas(caminho, pagesize=A4)
    largura, altura = A4

    c.setFont("Helvetica-Bold", 14)
    c.drawString(40, altura - 40, "Requisição de Compra")

    y = altura - 70
    c.setFont("Helvetica-Bold", 10)
    c.drawString(40, y, "Material")
    c.drawString(260, y, "Un.")
    c.drawString(330, y, "Seção")
    c.drawString(430, y, "Qtd.")
    y -= 15
    c.line(40, y, 550, y)
    y -= 10

    c.setFont("Helvetica", 9)
    for p in lista:
        if y < 50:
            c.showPage()
            y = altura - 50
        c.drawString(40, y, p["nome"][:40].upper())
        c.drawString(260, y, (p["unidade"] or "-"))
        c.drawString(330, y, (p["secao"] or "-"))
        c.drawString(430, y, str(p["quantidade"]))
        y -= 14

    c.save()
    return caminho

PALAVRAS_IGNORAR = [
    "DE", "DA", "DO", "PARA", "PAR", "P/", " ", 
    "MATERIAIS", "MATERIAL", "CX", "PC", "PÇ", "KG"
]

def limpar_nome(nome):
    nome = nome.upper()

    # Remove tamanhos (32MM, 3/4, 1/2, 50MM…)
    nome = re.sub(r'\b\d+(MM|CM|M|KG)?\b', '', nome)
    nome = re.sub(r'\b\d+/\d+\b', '', nome)

    # Remove caracteres especiais
    nome = re.sub(r'[^\w\s]', '', nome)

    # Remove palavras ignoradas
    for p in PALAVRAS_IGNORAR:
        nome = nome.replace(p, " ")

    # Remove espaços duplicados
    return " ".join(nome.split()).strip()

# -------------- EXTRAÇÃO DE XML --------------
def extrair_itens_xml(caminho_xml):
    try:
        with open(caminho_xml, "rb") as f:
            dados = xmltodict.parse(f)
        itens = []
        for det in dados["nfeProc"]["NFe"]["infNFe"]["det"]:
            nome = det["prod"]["xProd"]
            qtd = float(det["prod"]["qCom"])
            unidade = det["prod"]["uCom"]
            itens.append({"nome": nome, "qtd": int(qtd), "unidade": normalizar_unidade(unidade)})
        return itens
    except:
        return []

    itens = []
    for prod in det:
        p = prod["prod"]
        nome = p["xProd"]
        qtd = float(p["qCom"])
        itens.append({"nome": nome, "qtd": int(qtd)})

    # Agrupar e somar
    agrupado = defaultdict(int)
    for item in itens:
        agrupado[item["nome"]] += item["qtd"]

    return [{"nome": nome, "qtd": qtd} for nome, qtd in agrupado.items()]

# -------------- EXTRAÇÃO DANFE PDF --------------
def extrair_itens_pdf(caminho_pdf):
    import PyPDF2
    import re

    unidades_map = {
        "UN": "UN", "UND": "UN", "UNID": "UN", "UNIDADE": "UN",
        "M": "M", "MT": "M", "METRO": "M", "METROS": "M",
        "KG": "KG", "KILO": "KG", "QUILO": "KG",
        "CX": "CX", "CAIXA": "CX", "CX.": "CX",
        "PÇ": "PÇ", "PECA": "PÇ", "PEÇA": "PÇ", "PC": "PÇ",
        "RL": "RL", "ROLO": "RL",
        "CJ": "CJ", "CONJ": "CJ",
    }

    with open(caminho_pdf, "rb") as f:
        leitor = PyPDF2.PdfReader(f)
        texto = ""
        for pagina in leitor.pages:
            texto += pagina.extract_text() + "\n"

    # Normalizar quebra e espaços
    linhas = [l.strip() for l in texto.split("\n") if l.strip()]

    itens = []
    item_atual = {"nome": None, "unidade": None, "secao": None, "qtd": None}

    # Identificadores (EXATAMENTE como no seu PDF)
    for i, linha in enumerate(linhas):
        if linha.startswith("Material:"):
            item_atual = {"nome": None, "unidade": None, "secao": None, "qtd": None}
            item_atual["nome"] = linha.replace("Material:", "").strip()

        elif linha.startswith("Unidade:"):
            un = linha.replace("Unidade:", "").strip().upper()
            item_atual["unidade"] = unidades_map.get(un, un)

        elif linha.startswith("Seção:"):
            sec = linha.replace("Seção:", "").strip().upper()  # SALVA SEÇÃO EM MAIÚSCULO
            item_atual["secao"] = sec

        elif linha.startswith("Quantidade em todos os estoques:"):
            qtd_str = linha.replace("Quantidade em todos os estoques:", "").strip()
            qtd = re.sub(r"[^0-9]", "", qtd_str)  # tira vírgula, letras, símbolos
            item_atual["qtd"] = int(qtd) if qtd.isdigit() else 0
            itens.append(item_atual)

    return itens


# Permitir função fuzzy no HTML
def buscar_similares(nome_xml):
    nome_limpo = limpar_nome(nome_xml)
    semelhantes = []
    produtos = Produto.query.all()

    for prod in produtos:
        nome_prod_limpo = limpar_nome(prod.nome)
        similar = fuzz.token_set_ratio(nome_limpo, nome_prod_limpo)
        if similar >= 75:  # Limite balanceado
            semelhantes.append({"id": prod.id, "nome": prod.nome, "sim": similar})

    # Ordena por similaridade (maior primeiro)
    return sorted(semelhantes, key=lambda x: x["sim"], reverse=True)

# -------------- EXTRAÇÃO DANFE EXCEL --------------

def extrair_itens_excel(caminho_excel):
    import pandas as pd

    unidades_map = {
        "UN": "UN", "UND": "UN", "UNID": "UN", "UNIDADE": "UN",
        "M": "M", "MT": "M", "METRO": "M", "METROS": "M",
        "KG": "KG", "KILO": "KG", "QUILO": "KG",
        "CX": "CX", "CAIXA": "CX", "CX.": "CX",
        "PÇ": "PÇ", "PECA": "PÇ", "PEÇA": "PÇ", "PC": "PÇ",
        "RL": "RL", "ROLO": "RL",
        "CJ": "CJ", "CONJ": "CJ"
    }

    df = pd.read_excel(caminho_excel)

    # Debug de coluna (opcional)
    print(">>> COLUNAS ENCONTRADAS NO EXCEL:", df.columns.tolist())

    # Normaliza nomes
    df.columns = df.columns.str.strip().str.lower()

    # Renomeia colunas aceitas
    renomear = {
        "seção": "secao",
        "quantidade em estoque": "quantidade"
    }
    df = df.rename(columns=renomear)

    # Verifica obrigatórias
    obrigatorias = ["material", "unidade", "quantidade"]
    for col in obrigatorias:
        if col not in df.columns:
            return None

    # Seção opcional
    tem_secao = "secao" in df.columns

    itens = []
    for _, row in df.iterrows():
        nome = str(row["material"]).strip()

        unidade = str(row["unidade"]).strip().upper()
        unidade = unidades_map.get(unidade, unidade)

        secao = str(row["secao"]).strip().upper() if tem_secao else None

        try:
            qtd = int(row["quantidade"])
        except:
            qtd = 0

        itens.append({
            "nome": nome,
            "unidade": unidade,
            "secao": secao,
            "qtd": qtd
        })

    return itens

# -------------- PADRONIZAÇÃO DE UNIDADES --------------
def normalizar_unidade(u):
    if not u:
        return None
    u = u.strip().lower()

    tabela = {
        "m": "M", "mt": "M", "metro": "M", "metros": "M",
        "pç": "PÇ", "pc": "PÇ", "peça": "PÇ", "peca": "PÇ", "pz": "PÇ",
        "cx": "CX", "caixa": "CX",
        "kg": "KG", "quilo": "KG", "kilo": "KG"
    }
    return tabela.get(u, u.upper())

# -------------- EXTRAÇÃO XML EMBUTIDO NO PDF --------------
def extrair_xml_do_pdf(caminho_pdf):
    try:
        txt = ""
        with open(caminho_pdf, "rb") as f:
            leitor = PyPDF2.PdfReader(f)
            for p in leitor.pages:
                txt += p.extract_text()

        inicio = txt.find("<nfeProc")
        if inicio == -1:
            inicio = txt.find("<NFe")
        if inicio == -1:
            return None

        xml = txt[inicio:]
        xml = xml.split("</nfeProc>")[0] + "</nfeProc>"
        caminho = os.path.join("static", "nftemp_pdf.xml")
        with open(caminho, "w", encoding="utf-8") as f:
            f.write(xml)
        return caminho
    except:
        return None

# ============================================
# LOGIN USER LOADER
# ============================================
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# ============================================
# ROTAS
# ============================================

@app.route("/")
def index():
    return redirect(url_for("dashboard"))


# --------------------------------------------
# LOGIN
# --------------------------------------------
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        user = User.query.filter_by(username=request.form["username"]).first()
        if user and check_password_hash(user.password, request.form["password"]):
            if not user.ativo:
                flash("Usuário bloqueado!", "danger")
                return redirect(url_for("login"))
            login_user(user)
            return redirect(url_for("dashboard"))
        flash("Credenciais inválidas", "danger")
    return render_template("login.html")


@app.route("/logout")
def logout():
    logout_user()
    return redirect(url_for("login"))


# --------------------------------------------
# DASHBOARD
# --------------------------------------------
@app.route("/dashboard")
@login_required
def dashboard():
    total_itens = Produto.query.count()
    baixo = Produto.query.filter(Produto.quantidade < 10).count()
    secoes = Secao.query.count()
    itens_baixos = Produto.query.filter(Produto.quantidade < 10).join(Secao).all()

    return render_template("dashboard.html",
                           total_itens=total_itens,
                           baixo=baixo,
                           secoes=secoes,
                           itens_baixos=itens_baixos)


# --------------------------------------------
# SEÇÕES
# --------------------------------------------
@app.route("/secoes", methods=["GET", "POST"])
@login_required
def secoes():
    if current_user.role not in ["admin", "estoquista"]:
        flash("Acesso negado", "danger")
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        nome = request.form.get("nome")
        descricao = request.form.get("descricao")
        if not nome:
            flash("Nome obrigatório!", "danger")
            return redirect(url_for("secoes"))

        nova = Secao(nome=nome, descricao=descricao)
        db.session.add(nova)
        db.session.commit()

        registrar_log(current_user.username, "CRIAR SEÇÃO", nome)

        flash("Seção criada com sucesso!", "success")
        return redirect(url_for("secoes"))

    secoes = Secao.query.order_by(Secao.nome.asc()).all()
    return render_template("secoes.html", secoes=secoes)

@app.route("/api/itens_por_secao/<int:secao_id>")
def itens_por_secao(secao_id):
    produtos = Produto.query.filter_by(secao_id=secao_id).all()
    return {
        "itens": [
            {"id": p.id, "nome": p.nome}
            for p in produtos
        ]
    }

# ============================================
# EDITAR SEÇÃO
# ============================================
@app.route("/secoes/editar/<int:secao_id>", methods=["GET", "POST"])
@login_required
def editar_secao(secao_id):
    if current_user.role not in ["admin", "estoquista"]:
        flash("Acesso negado!", "danger")
        return redirect(url_for("secoes"))

    secao = Secao.query.get(secao_id)
    if not secao:
        flash("Seção não encontrada!", "danger")
        return redirect(url_for("secoes"))

    if request.method == "POST":
        secao.nome = request.form.get("nome")
        secao.descricao = request.form.get("descricao")
        db.session.commit()

        registrar_log(current_user.username, "EDITAR SEÇÃO", secao.nome)

        flash("Seção atualizada com sucesso!", "success")
        return redirect(url_for("secoes"))

    return render_template("secoes_editar.html", secao=secao)

# ============================================
# EXCLUIR SEÇÃO
# ============================================
@app.route("/secoes/excluir/<int:secao_id>")
@login_required
def excluir_secao(secao_id):
    if current_user.role not in ["admin", "estoquista"]:
        flash("Acesso negado!", "danger")
        return redirect(url_for("secoes"))

    secao = Secao.query.get(secao_id)
    if not secao:
        flash("Seção não encontrada!", "danger")
        return redirect(url_for("secoes"))

    # Verificar se existe produto usando essa seção
    produtos = Produto.query.filter_by(secao_id=secao_id).all()
    if produtos:
        flash("Não é possível excluir a seção! Existem produtos vinculados a ela.", "danger")
        return redirect(url_for("secoes"))

    registrar_log(current_user.username, "EXCLUIR SEÇÃO", secao.nome)

    db.session.delete(secao)
    db.session.commit()

    flash("Seção excluída com sucesso!", "success")
    return redirect(url_for("secoes"))

# --------------------------------------------
# ESTOQUE LISTAGEM
# --------------------------------------------
@app.route("/estoque")
@login_required
def estoque():
    busca = request.args.get("q")
    if busca:
        produtos = Produto.query.filter(Produto.nome.contains(busca)).all()
    else:
        produtos = Produto.query.all()
    return render_template("estoque_lista.html", produtos=produtos)


# --------------------------------------------
# CADASTRAR ITEM (ENTRADA INICIAL REGISTRADA)
# --------------------------------------------
@app.route("/add", methods=["GET", "POST"])
@login_required
def add_item():
    if current_user.role not in ["admin", "estoquista"]:
        return redirect(url_for("estoque"))

    secoes = Secao.query.all()

    if request.method == "POST":
        nome = request.form["nome"]

        # 🔧 PERMITIR CADASTRO COM QUANTIDADE ZERO
        qtd = int(request.form.get("quantidade", 0))
        if qtd < 0:
            qtd = 0

        secao_id = request.form["secao_id"]

        foto = request.files.get("foto")
        foto_name = None
        if foto and foto.filename:
            foto_name = secure_filename(f"{datetime.now().timestamp()}_{foto.filename}")
            foto.save(os.path.join(UPLOAD_FOLDER, foto_name))

        novo = Produto(nome=nome, quantidade=qtd, secao_id=secao_id, foto=foto_name)
        db.session.add(novo)
        db.session.commit()

        # 🔧 SÓ REGISTRAR MOVIMENTAÇÃO SE QUANTIDADE > 0
        if qtd > 0:
            registrar_movimentacao(
                novo, current_user.username,
                acao="CADASTRO DE ITEM", entrada=qtd,
                obs="Entrada inicial"
            )

        registrar_log(current_user.username, "CADASTRO DE ITEM", nome)

        flash("Item cadastrado com sucesso!", "success")
        return redirect(url_for("estoque"))

    return render_template("estoque_adicionar.html", secoes=secoes)

# --------------------------------------------
# ADICIONAR MATERIAL
# --------------------------------------------
@app.route("/adicionar_material", methods=["GET", "POST"])
@login_required
def adicionar_material():
    produto_id = request.args.get("produto")
    produto = db.session.get(Produto, produto_id)

    if not produto:
        flash("Produto não encontrado!", "danger")
        return redirect(url_for("estoque"))

    if request.method == "POST":
        qtd = int(request.form.get("quantidade"))
        obs = request.form.get("obs")

        produto.quantidade += qtd
        db.session.commit()

        registrar_movimentacao(
            produto,
            current_user.username,
            acao="ADICIONAR MATERIAL",
            entrada=qtd,
            obs=obs
        )

        registrar_log(current_user.username, "ADICIONAR MATERIAL", f"{produto.nome} +{qtd}")

        flash(f"{qtd} unidade(s) adicionada(s) ao item {produto.nome}.", "success")
        return redirect(url_for("estoque"))

    return render_template("adicionar_material.html", produto=produto)


# --------------------------------------------
# RETIRADA
# --------------------------------------------
@app.route("/retirada", methods=["GET", "POST"])
@login_required
def retirada():
    produtos = Produto.query.all()

    if request.method == "POST":
        pid = request.form.get("produto_id")
        qtd = request.form.get("quantidade")

        if not pid or not qtd:
            flash("Selecione um item e informe a quantidade.", "danger")
            return redirect(url_for("retirada"))

        item = db.session.get(Produto, int(pid))
        if not item:
            flash("Item não encontrado!", "danger")
            return redirect(url_for("retirada"))

        qtd = int(qtd)
        if qtd > item.quantidade:
            flash("Estoque insuficiente!", "danger")
            return redirect(url_for("retirada"))

        item.quantidade -= qtd
        db.session.commit()

        registrar_movimentacao(
            item, current_user.username,
            acao="RETIRADA DE MATERIAL",
            retirada=qtd,
            obs=request.form.get("obs")
        )

        registrar_log(current_user.username, "RETIRADA", f"{item.nome} -{qtd}")

        flash("Retirada registrada com sucesso!", "success")
        return redirect(url_for("estoque"))

    return render_template("estoque_retirada.html", produtos=produtos)


# --------------------------------------------
# EDITAR ITEM (AJUSTE AUTOMÁTICO)
# --------------------------------------------
@app.route("/estoque/editar/<int:produto_id>", methods=["GET", "POST"])
@login_required
def editar_produto(produto_id):
    produto = db.session.get(Produto, produto_id)
    if not produto:
        flash("Produto não encontrado!", "danger")
        return redirect(url_for("estoque"))

    secoes = Secao.query.all()

    if request.method == "POST":
        old_qtd = produto.quantidade

        produto.nome = request.form.get("nome")

        # 🔧 PERMITIR ALTERAR PARA 0 SEM BUG
        nova_qtd = int(request.form.get("quantidade", 0))
        if nova_qtd < 0:
            nova_qtd = 0

        produto.secao_id = int(request.form.get("secao_id"))

        produto.quantidade = nova_qtd
        db.session.commit()

        diff = nova_qtd - old_qtd

        # 🔧 SÓ REGISTRAR SE ALTERAR VALOR
        if diff != 0:
            registrar_movimentacao(
                produto,
                current_user.username,
                acao="AJUSTE DE ESTOQUE",
                entrada=diff if diff > 0 else 0,
                retirada=abs(diff) if diff < 0 else 0,
                obs="Ajuste manual"
            )

        registrar_log(current_user.username, "EDITAR ITEM", produto.nome)

        flash("Produto atualizado com sucesso!", "success")
        return redirect(url_for("estoque"))

    return render_template("estoque_editar.html", produto=produto, secoes=secoes)

@app.route("/entrada_nf_excel", methods=["POST"])
@login_required
def entrada_nf_excel():
    file = request.files.get("xlsx_file")
    if not file:
        flash("Nenhum arquivo Excel selecionado!", "warning")
        return redirect(url_for("entrada_nf"))

    itens = extrair_itens_excel(file)

    return render_template("entrada_nf_confirmar.html", itens=itens)

# --------------------------------------------
# EXCLUIR ITEM
# --------------------------------------------
@app.route("/estoque/excluir/<int:produto_id>")
@login_required
def excluir_produto(produto_id):
    produto = db.session.get(Produto, produto_id)
    if not produto:
        flash("Produto não encontrado!", "danger")
        return redirect(url_for("estoque"))

    registrar_movimentacao(
        produto,
        current_user.username,
        acao="EXCLUSÃO DE ITEM",
        retirada=produto.quantidade,
        obs="Item excluído"
    )

    registrar_log(current_user.username, "EXCLUIR ITEM", produto.nome)

    db.session.delete(produto)
    db.session.commit()

    flash("Produto excluído com sucesso!", "success")
    return redirect(url_for("estoque"))


# --------------------------------------------
# RELATÓRIOS (HISTÓRICO COMPLETO)
# --------------------------------------------
@app.route("/relatorios")
@login_required
def relatorios():
    data_ini = request.args.get("data_ini")
    data_fim = request.args.get("data_fim")
    secao_id = request.args.get("secao_id")
    produto_id = request.args.get("produto_id")

    query = Movimentacao.query

    # Converter data DD/MM/AAAA para AAAA-MM-DD dentro do SQL
    data_convertida = func.substr(Movimentacao.data_hora, 7, 4) + "-" + \
                      func.substr(Movimentacao.data_hora, 4, 2) + "-" + \
                      func.substr(Movimentacao.data_hora, 1, 2)

    # FILTRAR DATA INICIAL
    if data_ini:
        query = query.filter(data_convertida >= data_ini)

    # FILTRAR DATA FINAL
    if data_fim:
        query = query.filter(data_convertida <= data_fim)

    # FILTRAR SEÇÃO
    if secao_id:
        secao = Secao.query.get(secao_id)
        if secao:
            query = query.filter(Movimentacao.secao == secao.nome)

    # FILTRAR ITEM
    if produto_id:
        produto = Produto.query.get(produto_id)
        if produto:
            query = query.filter(Movimentacao.produto == produto.nome)

    registros = query.order_by(Movimentacao.id.desc()).all()

    secoes = Secao.query.all()

    # Só carrega produtos se secao tiver sido escolhida
    produtos = Produto.query.filter_by(secao_id=secao_id).all() if secao_id else []

    dados = [{
        "data": r.data_hora,
        "produto": r.produto,
        "secao": r.secao,
        "entrada": r.entrada,
        "retirada": r.retirada,
        "usuario": r.usuario,
        "estoque_atual": r.estoque_atual,
        "obs": r.obs,
        "acao": r.acao
    } for r in registros]

    return render_template(
        "relatorios.html",
        registros=dados,
        secoes=secoes,
        produtos=produtos,
        data_ini=data_ini,
        data_fim=data_fim,
        secao_id=secao_id,
        produto_id=produto_id
    )
# ============================================
#           ROTA ENTRADA NF XML/PDF/EXCEL
# ============================================
@app.route("/entrada_nf", methods=["GET", "POST"])
@login_required
def entrada_nf():
    if current_user.role not in ["admin", "estoquista"]:
        flash("Acesso negado!", "danger")
        return redirect(url_for("dashboard"))

    import json, os
    from sqlalchemy import func

    # ====================== CONFIRMAR IMPORTAÇÃO ======================
    if request.method == "POST" and "confirmar" in request.form:
        try:
            with open("static/temp_nf.json", "r", encoding="utf-8") as f:
                itens = json.load(f)
        except:
            itens = []

        for idx, item in enumerate(itens):
            nome = item["nome"]
            unidade = (item.get("unidade") or "").upper()
            qtd = int(request.form.get(f"qtd_{idx}", item.get("qtd", 0)))

            # ======== Seção ========
            secao_nome = request.form.get(f"secao_{idx}", item.get("secao"))
            sec = None
            if secao_nome:
                sec = Secao.query.filter(func.upper(Secao.nome) == secao_nome.upper()).first()
                if not sec:
                    sec = Secao(nome=secao_nome.upper())
                    db.session.add(sec)
                    db.session.commit()

            # ======== Similaridade (usar item existente) ========
            escolha = request.form.get(f"match_{idx}")

            if escolha and escolha != "novo":
                p = db.session.get(Produto, int(escolha))

                # Atualiza unidade/seção se o item ainda não tiver
                if unidade and (not p.unidade):
                    p.unidade = unidade
                if sec and not p.secao_id:
                    p.secao_id = sec.id

                # Só altera estoque se quantidade > 0
                if qtd > 0:
                    p.quantidade += qtd
                    db.session.commit()
                    registrar_movimentacao(p, current_user.username, "ENTRADA NF", entrada=qtd)
                else:
                    db.session.commit()

            else:
                # ======== Criar novo item ========
                novo = Produto(
                    nome=nome.upper(),
                    quantidade=qtd,
                    unidade=unidade,
                    secao_id=sec.id if sec else None
                )
                db.session.add(novo)
                db.session.commit()

                if qtd > 0:
                    registrar_movimentacao(novo, current_user.username, "ENTRADA NF", entrada=qtd)

        # Apaga temp
        if os.path.exists("static/temp_nf.json"):
            os.remove("static/temp_nf.json")

        flash("Itens importados com sucesso!", "success")
        return render_template("entrada_nf.html")

        # ====================== UPLOAD NF (Excel / PDF / XML) ======================
    if request.method == "POST":

        # ----------- Função para adicionar similares -----------
        def adicionar_similares(itens):
            for it in itens:
                it["similares"] = buscar_similares(it["nome"])
            return itens

        # ------------- EXCEL -------------
        excel = request.files.get("xlsx_file")
        if excel and excel.filename.lower().endswith((".xls", ".xlsx")):
            caminho_excel = os.path.join("static", "nf_temp.xlsx")
            excel.stream.seek(0)
            with open(caminho_excel, "wb") as f:
                f.write(excel.read())

            itens = extrair_itens_excel(caminho_excel)
            if not itens:
                flash("Nenhum item encontrado no Excel enviado ou colunas inválidas!", "danger")
                return redirect(url_for("entrada_nf"))

            itens = adicionar_similares(itens)

            with open("static/temp_nf.json", "w", encoding="utf-8") as f:
                json.dump(itens, f, ensure_ascii=False, indent=2)

            flash("Itens extraídos com sucesso do Excel!", "success")
            secoes = Secao.query.order_by(Secao.nome).all()
            return render_template("entrada_nf_confirmar.html", itens=itens, secoes=secoes)


                # ------------- PDF -------------
        pdf = request.files.get("pdf_file")
        if pdf and pdf.filename.lower().endswith(".pdf"):
            caminho_pdf = os.path.join("static", "nf_temp.pdf")
            pdf.stream.seek(0)
            with open(caminho_pdf, "wb") as f:
                f.write(pdf.read())

            itens = extrair_itens_pdf(caminho_pdf)
            if not itens:
                itens = extrair_itens_relatorio_pdf(caminho_pdf)

            if not itens:
                flash("Nenhum item encontrado no PDF enviado!", "danger")
                return redirect(url_for("entrada_nf"))

            itens = adicionar_similares(itens)

            with open("static/temp_nf.json", "w", encoding="utf-8") as f:
                json.dump(itens, f, ensure_ascii=False, indent=2)

            flash("Itens extraídos com sucesso do PDF!", "success")
            secoes = Secao.query.order_by(Secao.nome).all()
            return render_template("entrada_nf_confirmar.html", itens=itens, secoes=secoes)

    # ------------- XML -------------
        xml = request.files.get("xml_file")
        if xml and xml.filename.lower().endswith(".xml"):
            caminho_xml = os.path.join("static", "nf_temp.xml")
            xml.stream.seek(0)
            with open(caminho_xml, "wb") as f:
                f.write(xml.read())

            itens = extrair_itens_xml(caminho_xml)
            if not itens:
                flash("Nenhum item encontrado no XML enviado!", "danger")
                return redirect(url_for("entrada_nf"))

            itens = adicionar_similares(itens)

            with open("static/temp_nf.json", "w", encoding="utf-8") as f:
                json.dump(itens, f, ensure_ascii=False, indent=2)

            flash("Itens extraídos com sucesso do XML!", "success")
            secoes = Secao.query.order_by(Secao.nome).all()
            return render_template("entrada_nf_confirmar.html", itens=itens, secoes=secoes)

    # GET NORMAL
    return render_template("entrada_nf.html")


@app.route("/requisicao_compra", methods=["GET", "POST"])
@login_required
def requisicao_compra():
    if current_user.role not in ["admin", "estoquista"]:
        flash("Acesso negado!", "danger")
        return redirect(url_for("dashboard"))

    # -----------------------------------
    # GET → MOSTRA A TABELA PARA EDITAR ITENS
    # -----------------------------------
    if request.method == "GET":
        itens = Produto.query.filter(Produto.quantidade < 10).all()
        return render_template("requisicao_compra.html", itens=itens)

    # -----------------------------------
    # POST → PREPARA ITENS ESCOLHIDOS + MANUAIS
    # -----------------------------------
    selecionados = []

    # 1) Itens marcados na tabela
    for key, value in request.form.items():
        if key.startswith("item_"):
            pid = key.split("_")[1]
            qtd = int(request.form.get(f"qtd_{pid}", 0))
            if qtd > 0:
                produto = Produto.query.get(int(pid))
                selecionados.append({
                    "nome": produto.nome,
                    "unidade": produto.unidade or "-",
                    "secao": produto.secao.nome if produto.secao else "-",
                    "quantidade": qtd
                })

    # 2) Item manual (opcional)
    nome_manual = request.form.get("manual_nome")
    qtd_manual = request.form.get("manual_qtd")

    if nome_manual and qtd_manual:
        try:
            qtd_manual = int(qtd_manual)
            if qtd_manual > 0:
                selecionados.append({
                    "nome": nome_manual.upper(),
                    "unidade": request.form.get("manual_unid") or "-",
                    "secao": request.form.get("manual_secao") or "-",
                    "quantidade": qtd_manual
                })
        except:
            pass  # se não for número, simplesmente ignora

@app.route("/entrada_nf_pdf", methods=["POST"])
@login_required
def entrada_nf_pdf():
    if current_user.role not in ["admin", "estoquista"]:
        flash("Acesso negado!", "danger")
        return redirect(url_for("dashboard"))

    import json, os

    pdf = request.files.get("pdf_file")
    if not pdf:
        flash("Nenhum arquivo PDF selecionado!", "warning")
        return redirect(url_for("entrada_nf"))

    # Salvar arquivo temporário
    caminho_pdf = os.path.join("static", "nf_temp.pdf")
    pdf.stream.seek(0)
    with open(caminho_pdf, "wb") as f:
        f.write(pdf.read())

    # Tentar extrair itens
    itens = extrair_itens_pdf(caminho_pdf)

    # Caso não seja NF padrão, tenta modelo alternativo
    if not itens:
        itens = extrair_itens_relatorio_pdf(caminho_pdf)

    if not itens:
        flash("Nenhum item encontrado no PDF enviado!", "danger")
        return redirect(url_for("entrada_nf"))

    # Salvar itens temporariamente em JSON
    with open("static/temp_nf.json", "w", encoding="utf-8") as f:
        json.dump(itens, f, ensure_ascii=False, indent=2)

    flash("Itens extraídos com sucesso do PDF!", "success")
    secoes = Secao.query.order_by(Secao.nome).all()
    return render_template("entrada_nf_confirmar.html", itens=itens, secoes=secoes)


    # -----------------------------------
    # SE NADA FOI SELECIONADO OU ADICIONADO
    # -----------------------------------
    if not selecionados:
        flash("Nenhum item foi selecionado ou uma quantidade inválida foi informada!", "warning")
        return redirect(url_for("requisicao_compra"))

    # -----------------------------------
    # SALVAR TEMPORARIAMENTE PARA O PDF + EMAIL
    # -----------------------------------
    import json, os
    with open("static/requisicao_temp.json", "w", encoding="utf-8") as f:
        json.dump(selecionados, f, ensure_ascii=False, indent=2)

    return redirect(url_for("enviar_requisicao_email"))



@app.route("/enviar_requisicao_email")
@login_required
def enviar_requisicao_email():
    import json, os

    if not os.path.exists("static/requisicao_temp.json"):
        flash("Nenhuma requisição foi preparada!", "danger")
        return redirect(url_for("dashboard"))

    with open("static/requisicao_temp.json", "r", encoding="utf-8") as f:
        itens = json.load(f)

    # ---- Gera PDF somente com os itens escolhidos ----
    caminho = gerar_pdf_requisicao_selecionada(itens)

    assunto = "Requisição de compra - Estoque baixo"
    corpo = "Segue requisição de compra dos itens selecionados."

    enviar_email_requisicao(assunto, corpo, caminho)
    os.remove("static/requisicao_temp.json")

    flash("Requisição enviada com sucesso!", "success")
    return redirect(url_for("dashboard"))

    # -----------------------------------
    # GET → MOSTRA ITENS DE ESTOQUE BAIXO COM OPÇÃO DE EDITAR/REMOVER
    # -----------------------------------
    itens = Produto.query.filter(Produto.quantidade < 10).all()
    return render_template("requisicao_compra.html", itens=itens)



    # =======================================
    # CONFIRMAR IMPORTAÇÃO
    # =======================================
    if request.method == "POST" and "confirmar" in request.form:
        itens = session.get("itens_nf", [])

        for idx, item in enumerate(itens):
            nome = item["nome"]
            unidade = (item.get("unidade") or "").upper()
            qtd = int(request.form.get(f"qtd_{idx}", item.get("qtd", 0)))

            # ======== Seção ========
            secao_nome = item.get("secao")
            sec = None
            if secao_nome:
                sec = Secao.query.filter(func.upper(Secao.nome) == secao_nome.upper()).first()
                if not sec:
                    sec = Secao(nome=secao_nome.upper())
                    db.session.add(sec)
                    db.session.commit()

            # ======== Similaridade (usar existente) ========
            escolha = request.form.get(f"match_{idx}")
            if escolha and escolha != "novo":
                p = db.session.get(Produto, int(escolha))

                # Só altera estoque se quantidade > 0
                if qtd > 0:
                    p.quantidade += qtd
                    db.session.commit()
                    registrar_movimentacao(p, current_user.username, "ENTRADA NF", entrada=qtd)
                else:
                    db.session.commit()

            # ======== Criar novo item ========
            else:
                novo = Produto(
                    nome=nome,
                    quantidade=qtd,
                    unidade=unidade,
                    secao_id=sec.id if sec else None
                )
                db.session.add(novo)
                db.session.commit()

                # Registrar movimentação somente se quantidade > 0
                if qtd > 0:
                    registrar_movimentacao(novo, current_user.username, "ENTRADA NF", entrada=qtd)

        session.pop("itens_nf", None)
        flash("Itens importados com sucesso!", "success")
        return redirect(url_for("estoque"))

    return render_template("entrada_nf.html")


    # CONFIRMAR IMPORTAÇÃO
    if request.method == "POST" and "confirmar" in request.form:
        itens = session.get("itens_nf", [])

        for idx, item in enumerate(itens):
            nome = item["nome"]
            unidade = (item.get("unidade") or "").upper()
            qtd = int(request.form.get(f"qtd_{idx}", item.get("qtd", 0)))

            # ======== Seção ========
            secao_nome = item.get("secao")
            sec = None
            if secao_nome:
                sec = Secao.query.filter(func.upper(Secao.nome) == secao_nome.upper()).first()
                if not sec:
                    sec = Secao(nome=secao_nome.upper())
                    db.session.add(sec)
                    db.session.commit()

            # ======== Similaridade (usar existente) ========
            escolha = request.form.get(f"match_{idx}")
            if escolha and escolha != "novo":
                p = db.session.get(Produto, int(escolha))

                if qtd > 0:
                    p.quantidade += qtd
                    db.session.commit()
                    registrar_movimentacao(p, current_user.username, "ENTRADA NF", entrada=qtd)
                else:
                    db.session.commit()

            # ======== Criar novo item ========
            else:
                novo = Produto(
                    nome=nome,
                    quantidade=qtd,
                    unidade=unidade,
                    secao_id=sec.id if sec else None
                )
                db.session.add(novo)
                db.session.commit()

                if qtd > 0:
                    registrar_movimentacao(novo, current_user.username, "ENTRADA NF", entrada=qtd)

        session.pop("itens_nf", None)
        flash("Itens importados com sucesso!", "success")
        return redirect(url_for("estoque"))
# --------------------------------------------
# RELATÓRIO EXCEL
# --------------------------------------------
@app.route("/modelo_excel_nf")
@login_required
def modelo_excel_nf():
    colunas = ["Material", "Unidade", "Seção", "Quantidade"]
    modelo = pd.DataFrame(columns=colunas)
    caminho = os.path.join("static", "modelo_nf.xlsx")
    modelo.to_excel(caminho, index=False)

    return send_file(caminho, as_attachment=True)

@app.route("/relatorios/excel")
@login_required
def relatorios_excel():
    import pandas as pd
    registros = Movimentacao.query.order_by(Movimentacao.id.desc()).all()

    dados = [{
        "Data/Hora": r.data_hora,
        "Item": r.produto,
        "Seção": r.secao,
        "Entrada": r.entrada,
        "Retirada": r.retirada,
        "Usuário": r.usuario,
        "Estoque Atual": r.estoque_atual,
        "Observação": r.obs,
        "Ação": r.acao
    } for r in registros]

    df = pd.DataFrame(dados)
    file_path = os.path.join("static", "relatorio.xlsx")
    df.to_excel(file_path, index=False)
    return redirect("/static/relatorio.xlsx")


# --------------------------------------------
# RELATÓRIO PDF
# --------------------------------------------
@app.route("/relatorios/pdf")
@login_required
def relatorios_pdf():
    from reportlab.pdfgen import canvas
    from reportlab.lib.pagesizes import landscape, A4

    registros = Movimentacao.query.order_by(Movimentacao.id.desc()).all()
    file_path = os.path.join("static", "relatorio.pdf")
    c = canvas.Canvas(file_path, pagesize=landscape(A4))

    c.setFont("Helvetica-Bold", 12)
    c.drawString(30, 550, "Relatório de Movimentações de Estoque")
    y = 520
    c.setFont("Helvetica", 9)

    for r in registros:
        linha = (
            f"{r.data_hora} | {r.produto} ({r.secao}) | "
            f"+{r.entrada} / -{r.retirada} | "
            f"Estoque: {r.estoque_atual} | Usuário: {r.usuario}"
        )
        c.drawString(30, y, linha)
        y -= 14
        if y < 40:
            c.showPage()
            c.setFont("Helvetica", 9)
            y = 550

    c.save()
    return redirect("/static/relatorio.pdf")

def gerar_pdf_estoque_baixo():
    from reportlab.pdfgen import canvas
    from reportlab.lib.pagesizes import A4

    caminho = os.path.join("static", "requisicao_compra_estoque_baixo.pdf")

    c = canvas.Canvas(caminho, pagesize=A4)
    largura, altura = A4

    c.setFont("Helvetica-Bold", 14)
    c.drawString(40, altura - 40, "Requisição de Compra - Itens com Estoque Baixo")

    c.setFont("Helvetica", 10)
    c.drawString(40, altura - 60, f"Gerado em: {datetime.now().strftime('%d/%m/%Y %H:%M')}")

    y = altura - 90

    c.setFont("Helvetica-Bold", 10)
    c.drawString(40, y, "Material")
    c.drawString(260, y, "Seção")
    c.drawString(380, y, "Qtd Atual")
    y -= 15
    c.line(40, y, 550, y)
    y -= 10

    # Buscar itens com estoque baixo (< 10)
    itens = (
        Produto.query
        .filter(Produto.quantidade < 10)
        .order_by(Produto.secao_id, Produto.nome)
        .all()
    )

    c.setFont("Helvetica", 9)
    if not itens:
        c.drawString(40, y, "Nenhum item com estoque baixo no momento.")
    else:
        for p in itens:
            if y < 50:
                c.showPage()
                y = altura - 50
                c.setFont("Helvetica-Bold", 10)
                c.drawString(40, y, "Material")
                c.drawString(260, y, "Seção")
                c.drawString(380, y, "Qtd Atual")
                y -= 15
                c.line(40, y, 550, y)
                y -= 10
                c.setFont("Helvetica", 9)

            secao_nome = p.secao.nome.upper() if p.secao else "-"
            c.drawString(40, y, (p.nome or "")[:40].upper())
            c.drawString(260, y, secao_nome[:20])
            c.drawString(380, y, str(p.quantidade))
            y -= 14

    c.save()
    return caminho

def enviar_email_requisicao(assunto, corpo, anexo_caminho):
    if not all([EMAIL_HOST, EMAIL_PORT, EMAIL_USER, EMAIL_PASS, EMAIL_DESTINO]):
        print("⚠ E-mail não configurado corretamente (.env).")
        return False

    msg = MIMEMultipart()
    msg["From"] = EMAIL_USER
    msg["To"] = EMAIL_DESTINO
    msg["Subject"] = assunto

    msg.attach(MIMEText(corpo, "plain", "utf-8"))

    # Anexo
    try:
        with open(anexo_caminho, "rb") as f:
            part = MIMEBase("application", "octet-stream")
            part.set_payload(f.read())
        encoders.encode_base64(part)
        part.add_header(
            "Content-Disposition",
            f'attachment; filename="{os.path.basename(anexo_caminho)}"',
        )
        msg.attach(part)
    except Exception as e:
        print("Erro ao anexar arquivo:", e)
        return False

    try:
        server = smtplib.SMTP(EMAIL_HOST, EMAIL_PORT)
        server.starttls()
        server.login(EMAIL_USER, EMAIL_PASS)
        server.send_message(msg)
        server.quit()
        return True
    except Exception as e:
        print("Erro ao enviar e-mail:", e)
        return False

@app.route("/estoque_baixo/pdf")
@login_required
def estoque_baixo_pdf():
    if current_user.role not in ["admin", "estoquista"]:
        flash("Acesso negado!", "danger")
        return redirect(url_for("dashboard"))

    caminho = gerar_pdf_estoque_baixo()
    return send_file(caminho, as_attachment=True)

@app.route("/estoque_baixo/email")
@login_required
def estoque_baixo_email():
    if current_user.role not in ["admin", "estoquista"]:
        flash("Acesso negado!", "danger")
        return redirect(url_for("dashboard"))

    caminho = gerar_pdf_estoque_baixo()

    assunto = "Requisição de compra - Itens com estoque baixo"
    corpo = (
        "Olá,\n\n"
        "Segue em anexo a requisição de compra dos itens com estoque baixo, "
        f"gerada em {datetime.now().strftime('%d/%m/%Y %H:%M')}.\n\n"
        "Atenciosamente,\nSistema de Estoque"
    )

    ok = enviar_email_requisicao(assunto, corpo, caminho)

    if ok:
        flash("Requisição de compra enviada por e-mail com sucesso!", "success")
    else:
        flash("Não foi possível enviar o e-mail. Verifique as configurações.", "danger")

    return redirect(url_for("dashboard"))

# --------------------------------------------
# LOGS ADMINISTRATIVOS
# --------------------------------------------
@app.route("/logs")
@login_required
def logs():
    if current_user.role not in ["admin"]:
        flash("Acesso negado.", "danger")
        return redirect(url_for("dashboard"))

    registros = LogAcao.query.order_by(LogAcao.data.desc()).all()

    dados = [{
        "id": r.id,
        "usuario": r.usuario,
        "acao": r.acao,
        "data": r.data.strftime("%d/%m/%Y %H:%M")
    } for r in registros]

    return render_template("logs.html", logs=dados)


# --------------------------------------------
# USUÁRIOS
# --------------------------------------------
@app.route("/usuarios", methods=["GET", "POST"])
@login_required
def usuarios():
    if current_user.role != "admin":
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        username = request.form["username"]
        role = request.form["role"]

        existente = User.query.filter_by(username=username).first()
        if existente:
            flash(f"O usuário '{username}' já existe!", "danger")
            return redirect(url_for("usuarios"))

        senha = "20511243"
        hash_senha = generate_password_hash(senha)
        novo = User(username=username, password=hash_senha, role=role)
        db.session.add(novo)
        db.session.commit()

        registrar_log(current_user.username, "CRIAR USUÁRIO", username)

        flash(f"Usuário '{username}' criado com sucesso! Senha inicial: {senha}", "success")
        return redirect(url_for("usuarios"))

    usuarios = User.query.all()
    return render_template("usuarios.html", usuarios=usuarios)


# --------------------------------------------
# USUÁRIO — BLOQUEAR / DESBLOQUEAR
# --------------------------------------------
@app.route("/usuarios/bloquear/<int:user_id>")
@login_required
def bloquear_usuario(user_id):
    if current_user.role != "admin":
        flash("Acesso negado.", "danger")
        return redirect(url_for("usuarios"))

    user = User.query.get(user_id)
    if not user:
        flash("Usuário não encontrado.", "danger")
        return redirect(url_for("usuarios"))

    user.ativo = False
    db.session.commit()

    registrar_log(current_user.username, "BLOQUEAR USUÁRIO", user.username)

    flash(f"Usuário {user.username} bloqueado com sucesso!", "success")
    return redirect(url_for("usuarios"))


@app.route("/usuarios/desbloquear/<int:user_id>")
@login_required
def desbloquear_usuario(user_id):
    if current_user.role != "admin":
        flash("Acesso negado.", "danger")
        return redirect(url_for("usuarios"))

    user = User.query.get(user_id)
    if not user:
        flash("Usuário não encontrado.", "danger")
        return redirect(url_for("usuarios"))

    user.ativo = True
    db.session.commit()

    registrar_log(current_user.username, "DESBLOQUEAR USUÁRIO", user.username)

    flash(f"Usuário {user.username} desbloqueado com sucesso!", "success")
    return redirect(url_for("usuarios"))


@app.route("/usuarios/reset/<int:user_id>", methods=["POST"])
@login_required
def reset_senha(user_id):
    if current_user.role != "admin":
        flash("Acesso negado.", "danger")
        return redirect(url_for("usuarios"))

    nova_senha = request.form.get("nova_senha")
    if not nova_senha:
        flash("A nova senha é obrigatória!", "danger")
        return redirect(url_for("usuarios"))

    user = User.query.get(user_id)
    if not user:
        flash("Usuário não encontrado.", "danger")
        return redirect(url_for("usuarios"))

    user.password = generate_password_hash(nova_senha)
    db.session.commit()

    registrar_log(current_user.username, "RESET SENHA", user.username)

    flash(f"Senha do usuário {user.username} alterada com sucesso!", "success")
    return redirect(url_for("usuarios"))


# --------------------------------------------
# SCHEDULER DIÁRIO NO WHATSAPP
# --------------------------------------------
from apscheduler.schedulers.background import BackgroundScheduler

def resumo_diario():
    baixo = Produto.query.filter(Produto.quantidade < 10).all()
    if not baixo:
        return
    msg = "📊 *RESUMO DE ESTOQUE BAIXO*\n\n"
    for p in baixo:
        msg += f"🔻 {p.nome}: {p.quantidade} un.\n"
    enviar_whatsapp(msg)

def iniciar_scheduler():
    scheduler = BackgroundScheduler()
    scheduler.add_job(resumo_diario, "cron", hour=7, minute=0)
    scheduler.start()


# --------------------------------------------
# CRIAR ADMIN SE BANCO ESTIVER VAZIO
# --------------------------------------------
def criar_admin():
    if User.query.count() == 0:
        senha = "admin123"
        user = User(username="admin", password=generate_password_hash(senha), role="admin")
        db.session.add(user)
        db.session.commit()
        print("👤 Admin criado automaticamente")
        print("Usuário: admin  Senha:", senha)


# --------------------------------------------
# MAIN — EXECUÇÃO COM PYTHON
# --------------------------------------------
if __name__ == "__main__":
    with app.app_context():
        db.create_all()
        criar_admin()
    iniciar_scheduler()
    app.run(debug=True)

# ======= CORREÇÃO DE TABELA PRODUTO (AJUSTE UNIDADE) =======
@app.cli.command("ajustar_produto")
def ajustar_produto():
    from sqlalchemy import text

    with app.app_context():
        # 1. Tentar adicionar a coluna, se não existir
        try:
            db.session.execute(text("ALTER TABLE produto ADD COLUMN unidade VARCHAR(10);"))
            print("✔ Coluna 'unidade' adicionada com sucesso!")
        except Exception as e:
            print(f"⚠ Aviso: {e}")

        print("✔ Finalizado.")

