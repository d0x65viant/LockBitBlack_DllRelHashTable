import os
import json
import idaapi
import idautils
import idc
from Modules.WinApiHashSearcher import *

def Calc_Dll_Hash(dll_name):
	'''
	Алгоритм функции из семпла Lockbit Black,
	для вычисления хеша имени dll.'''
	mask = 0xFFFFFFFF
	result = 0
	for each in dll_name+'\x00':
		each = ord(each)
		if(each > 0x40 and each < 0x5b):
			each = each | 0x20
		result = (result >> 0xd) | (result << 0x13)
		result = (result+each) & mask
	return result


def Calc_Func_Hash(dll_name, func_name):
	'''
	Алгоритм функции из семпла Lockbit Black,
	для вычисления хеша имени функции.'''
	mask = 0xFFFFFFFF
	result = dll_name
	for each in func_name+'\x00':
		each = ord(each)
		result = (result >> 0xd) | (result << 0x13)
		result = (result+each) & mask
	return result



def dll_bind_hstble(address: int) -> dict[int:str]:
	'''
	Ищет хеш-таблицы, и извлекает первый элемент таблицы,
	сохраняя результат в формате. хеш (int): имя_таблицы (str).'''

	dw_dict = dict()
	ip = address
	while True:
		asm = idc.GetDisasm(ip)
		insn = idaapi.insn_t()
		size_ins = idaapi.decode_insn(insn, ip)

		if "dword" in asm:
			val_dw_ea = insn.Op1.value
			dw_stea   = asm.split(" ")[-1]
			dw_dict[idaapi.get_wide_dword(val_dw_ea) ^ 0x10035FFF] = dw_stea

		if "retn" in asm:
			return dw_dict

		ip+=size_ins


def format_json(data: dict, indent_size: int) -> dict:
	'''
	Преобразование json в приемлемый вид,
	для чтения, с отступами относительно его
	ключей.'''

	indent = ' ' * indent_size
	result = '{\n'
	for key, value in data.items():
		result += f'{indent}"{key}": {json.dumps(value)},\n'
	result = result.rstrip(',\n') + '\n'
	result += '}'
	return result



def main():
	# Адрес нужной функции со смещением относительно секции .text
	resapi_ea = [ea for ea in idautils.Segments() 
	if  idc.get_segm_name(ea) == ".text"][0] + 0x539c
	# Словарь со значениями хешей dll и названиями хеш-таблиц.
	bind: dict[int:str] = dll_bind_hstble(resapi_ea)
	# Список хешей.
	hases: list[int] = [hs for hs in bind]
	# Объект для поиска хеша среди DLL.
	srch = SysHashSearcher(None, Calc_Dll_Hash)
	# Поиск DLL по вычеслинным хешам.
	res_srch: iter  = srch.hash_search(hases)
	# Формирование json.
	for dle in res_srch:
		bind[dle[0]] = (dle[1], bind[dle[0]])

	# Преобразование хешей в шестндцатеричное значение.
	bind: dict[str:list[str]] = {hex(key):value for key,value in bind.items()}
	# Текущая директория скрипта.
	cur_dir: str = os.path.dirname(sys.argv[0])
	# Форматированный json с отступами относительно ключа.
	formatted_json: dict = format_json(bind, indent_size=4)
	# Запись результата.
	open(cur_dir+"\\"+"dll_hashes.json", "w").write(formatted_json)

if __name__ == '__main__':
	main()