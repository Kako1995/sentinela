@app.get("/baixar")
def baixar():
    nome = request.args.get("arquivo")
    caminho = os.path.join(PASTA, nome)
    return send_file(caminho)
