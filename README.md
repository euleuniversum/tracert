# Трассировка автономных систем
## Описание
Пользователь вводит доменное имя или IP-адрес. Осуществляется трассировка до указанного узла с использованием tracert. Определяется к какой автономной системе относится каждый из полученных IP-адресов маршрутизаторов, страна и провайдер при помощи http://ipinfo.io/.

Выход: для каждого IP-адреса выводится результат трассировки (или кусок результата до появления *** ), для "белых" IP-адресов из него указывается номер автономной системы
В итоге  получается таблица:
| No по порядку | IP | AS | Cтрана | Провайдер |
|---------------|----|----|--------|-----------|

## Запуск

```sh
python as.py [host]
```

`host` -  ip-адресс или доменное имя, до которого необходимо провести трассировку.

## Пример входных и выходных данных
![alt tag](https://sun9-4.userapi.com/impg/xE7AH1PDaTQnxVsrg2WyjpzwTn4HPhB4f-70zA/y1GH7hhGwsk.jpg?size=647x145&quality=96&sign=0176499abffb111c388b3540fda621cb&type=album)
![alt tag](https://sun9-37.userapi.com/impg/88kk-N4kTsh203CZeb6JJaDZnh5gtXkGmkYInw/fCbzPZUZB-w.jpg?size=620x193&quality=96&sign=400e1bce550e0f3fc9e225c0a297245c&type=album)

### Автор
Кошкина Наталья
МО-401
