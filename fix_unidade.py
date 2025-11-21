import sqlite3

con = sqlite3.connect("estoque.db")
cur = con.cursor()

try:
    cur.execute("ALTER TABLE produto ADD COLUMN unidade VARCHAR(10)")
    print("✔ Coluna 'unidade' adicionada com sucesso!")
except Exception as e:
    print("⚠ Aviso:", e)

# Preencher unidade vazia como UN
try:
    cur.execute("UPDATE produto SET unidade='UN' WHERE unidade IS NULL OR unidade=''")
    print("✔ Valores atualizados para 'UN'")
except Exception as e:
    print("⚠ Aviso:", e)

con.commit()
con.close()

print("\n>>> FINALIZADO COM SUCESSO <<<")
