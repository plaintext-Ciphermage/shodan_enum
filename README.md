Es un script para simplificarte la vida a la hora de realizar una enumeracion masiva de IPS en shodan

Dentro del script tienes que colocar tu API KEYS<img width="1144" height="643" alt="imagen" src="https://github.com/user-attachments/assets/f5e897d9-2f27-49a0-990f-33e2c5271212" />

Su uso basico: para realizar un escaneo a una sola ip, tambien te guarda un archivo en JSON. `python3 shodan_enum.py 8.8.8.8` <img width="982" height="703" alt="imagen" src="https://github.com/user-attachments/assets/cd8ab9a7-e3d6-42c8-bcce-5c4afcb00b9a" />

Todos los comando son:

`python3 shodan_enum.py 8.8.8.8` Para una sola Ip
`python3 shodan_enum.py 8.8.8.8 1.1.1.1` Para varias ip
`python3 shodan_enum.py ips.txt` Para utilizar con un archivo TXT
