import json
import secrets
import hashlib
import mysql.connector
import base64
import shutil
import bcrypt
from datetime import datetime
from pathlib import Path
from bottle import route, run, template, post, request, static_file

def loadDatabaseSettings(pathjs):
    pathjs = Path(pathjs)
    sjson = False
    if pathjs.exists():
        with pathjs.open() as data:
            sjson = json.load(data)
    return sjson

def getToken():
    return secrets.token_hex(32)

@post('/Registro')
def Registro():
    dbcnf = loadDatabaseSettings('db.json')
    db = mysql.connector.connect(
        host='localhost', port=dbcnf['port'],
        database=dbcnf['dbname'],
        user=dbcnf['user'],
        password=dbcnf['password']
    )
    if not request.json:
        return {"R": -1}
    R = 'uname' in request.json and 'email' in request.json and 'password' in request.json
    if not R:
        return {"R": -1}
    try:
        password_hash = bcrypt.hashpw(request.json['password'].encode(), bcrypt.gensalt()).decode()
        with db.cursor() as cursor:
            cursor.execute(
                'INSERT INTO Usuario VALUES(null, %s, %s, %s)',
                (request.json['uname'], request.json['email'], password_hash)
            )
            R = cursor.lastrowid
            db.commit()
        db.close()
    except Exception as e:
        print(e)
        return {"R": -2}
    return {"R": 0, "D": R}

@post('/Login')
def Login():
    dbcnf = loadDatabaseSettings('db.json')
    db = mysql.connector.connect(
        host='localhost', port=dbcnf['port'],
        database=dbcnf['dbname'],
        user=dbcnf['user'],
        password=dbcnf['password']
    )
    if not request.json:
        return {"R": -1}
    R = 'uname' in request.json and 'password' in request.json
    if not R:
        return {"R": -1}
    try:
        with db.cursor() as cursor:
            cursor.execute(
                'SELECT id, password FROM Usuario WHERE uname = %s',
                (request.json['uname'],)
            )
            R = cursor.fetchall()
    except Exception as e:
        print(e)
        db.close()
        return {"R": -2}
    if not R:
        db.close()
        return {"R": -3}
    if not bcrypt.checkpw(request.json['password'].encode(), R[0][1].encode()):
        db.close()
        return {"R": -3}
    T = getToken()
    try:
        with db.cursor() as cursor:
            cursor.execute('DELETE FROM AccesoToken WHERE id_Usuario = %s', (R[0][0],))
            cursor.execute('INSERT INTO AccesoToken VALUES(%s, %s, now())', (R[0][0], T))
            db.commit()
        db.close()
        return {"R": 0, "D": T}
    except Exception as e:
        print(e)
        db.close()
        return {"R": -4}

@post('/Imagen')
def Imagen():
    tmp = Path('tmp')
    if not tmp.exists():
        tmp.mkdir()
    img = Path('img')
    if not img.exists():
        img.mkdir()
    if not request.json:
        return {"R": -1}
    R = 'name' in request.json and 'data' in request.json and 'ext' in request.json and 'token' in request.json
    if not R:
        return {"R": -1}
    ALLOWED_EXTENSIONS = ['jpg', 'jpeg', 'png', 'gif', 'webp']
    if request.json['ext'].lower() not in ALLOWED_EXTENSIONS:
        return {"R": -4}
    dbcnf = loadDatabaseSettings('db.json')
    db = mysql.connector.connect(
        host='localhost', port=dbcnf['port'],
        database=dbcnf['dbname'],
        user=dbcnf['user'],
        password=dbcnf['password']
    )
    TKN = request.json['token']
    try:
        with db.cursor() as cursor:
            cursor.execute('SELECT id_Usuario FROM AccesoToken WHERE token = %s', (TKN,))
            R = cursor.fetchall()
    except Exception as e:
        print(e)
        db.close()
        return {"R": -2}
    if not R:
        db.close()
        return {"R": -5}
    id_Usuario = R[0][0]
    with open(f'tmp/{id_Usuario}', "wb") as imagen:
        imagen.write(base64.b64decode(request.json['data'].encode()))
    try:
        with db.cursor() as cursor:
            cursor.execute(
                'INSERT INTO Imagen VALUES(null, %s, %s, %s)',
                (request.json['name'], 'img/', id_Usuario)
            )
            cursor.execute('SELECT max(id) as idImagen FROM Imagen WHERE id_Usuario = %s', (id_Usuario,))
            R = cursor.fetchall()
            idImagen = R[0][0]
            cursor.execute('UPDATE Imagen SET ruta = %s WHERE id = %s', (f'img/{idImagen}.{request.json["ext"]}', idImagen))
            db.commit()
        shutil.move(f'tmp/{id_Usuario}', f'img/{idImagen}.{request.json["ext"]}')
        return {"R": 0, "D": idImagen}
    except Exception as e:
        print(e)
        db.close()
        return {"R": -3}

@post('/Descargar')
def Descargar():
    dbcnf = loadDatabaseSettings('db.json')
    db = mysql.connector.connect(
        host='localhost', port=dbcnf['port'],
        database=dbcnf['dbname'],
        user=dbcnf['user'],
        password=dbcnf['password']
    )
    if not request.json:
        return {"R": -1}
    R = 'token' in request.json and 'id' in request.json
    if not R:
        return {"R": -1}
    TKN = request.json['token']
    idImagen = request.json['id']
    try:
        with db.cursor() as cursor:
            cursor.execute('SELECT id_Usuario FROM AccesoToken WHERE token = %s', (TKN,))
            R = cursor.fetchall()
    except Exception as e:
        print(e)
        db.close()
        return {"R": -2}
    if not R:
        db.close()
        return {"R": -5}
    id_Usuario = R[0][0]
    try:
        with db.cursor() as cursor:
            cursor.execute(
                'SELECT name, ruta FROM Imagen WHERE id = %s AND id_Usuario = %s',
                (idImagen, id_Usuario)
            )
            R = cursor.fetchall()
    except Exception as e:
        print(e)
        db.close()
        return {"R": -3}
    if not R:
        db.close()
        return {"R": -6}
    print(Path("img").resolve(), R[0][1])
    return static_file(R[0][1], Path(".").resolve())

if __name__ == '__main__':
    run(host='0.0.0.0', port=443, debug=False, server='gunicorn', certfile='/opt/webapi/cert.pem', keyfile='/opt/webapi/key.pem')
