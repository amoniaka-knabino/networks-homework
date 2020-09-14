### Описание

Скрипт, отправляющий все картинки из папки по электронной почте во вложении

### Запуск:

python3 smtp_pic_sender.py -f from@mail.ru -t to@mail.ru -d ./images/ -s smtp.mail.ru:587 -ssl --auth --subject test_script --verbose
