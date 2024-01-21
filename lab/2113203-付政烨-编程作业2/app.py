from flask import Flask,render_template

app=Flask(__name__)

# 创建了网址 /show/info 和函数 index 的对应关系，以后用户在浏览器上访问 /show/info 网站自动执行 index
@app.route('/')
def index():
    # Flask会默认区templates文件夹中寻找文件，读取内容，给用户返回
    return render_template("index.html")

if __name__=='__main__':
    app.run(host='0.0.0.0', port=8080)