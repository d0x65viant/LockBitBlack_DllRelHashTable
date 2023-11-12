from typing import Callable, Iterator, Generator
import os
import sys
import json


class ArgsCallNotInit(Exception):
	def __init__(self, *args):
		if args:
			self.message = args[0]
		else:
			self.message = None

	def __str__(self):
		if self.message:
			return f" {self.message}"
		else:
			return f" Exception has been raised."


class SysHashSearcher:
	def __init__(self, 
		calc_hash_func_name: Callable, 
		calc_hash_dll_name: Callable,
		*args, **kwargs):

		mainargs_excpt = {
		not callable(calc_hash_func_name) and 
		not callable(calc_hash_dll_name): (ArgsCallNotInit, 
		"None of the arguments `calc_hash_func_name` and"
		" `calc_hash_dll_name` are callable.")}
		if True in mainargs_excpt:
			raise mainargs_excpt[True][0](
				  mainargs_excpt[True][1])

		self.calc_hash_func_name = calc_hash_func_name
		self.calc_hash_dll_name  = calc_hash_dll_name
		self.dlls_list = self.get_dllsys32()
		self.funcs = self.get_funcsys32()

		self.hash_dict =  {
		calc_hash_func_name(func_name):(func_name, dll_name)
		for dll_name, list_items in self.funcs.items()
		for func_name in list_items

		} if calc_hash_func_name and not calc_hash_dll_name else{

		calc_hash_func_name(func_name, calc_hash_dll_name(dll_name)):(func_name, dll_name)
		for dll_name, list_items in self.funcs.items()
		for func_name in list_items

		} if (calc_hash_func_name and calc_hash_dll_name) else {

		calc_hash_dll_name(dll_name):dll_name
		for dll_name in self.dlls_list
		
		} if (calc_hash_dll_name and not calc_hash_func_name) else None

	def get_dllsys32(self):
		script_path = sys.argv[0]
		cur_dir = os.path.dirname(script_path)
		with open(cur_dir+"\\"+"func_names.json") as jf:
			dlls = [key for key in json.load(jf)]
			return dlls

	def get_funcsys32(self):
		script_path = sys.argv[0]
		cur_dir = os.path.dirname(script_path)
		with open(cur_dir+"\\"+"func_names.json") as jf:
			return json.load(jf)

	def hash_search(self, hashes: Iterator) -> Generator:
		for hash_val in hashes:
			try:
				key_value = self.hash_dict[hash_val]
				func_name = key_value[1]
				
				if  (self.calc_hash_func_name and not self.calc_hash_dll_name):
					yield (
					hash_val, 
						
						(func_name, 
					
							(dll_name for dll_name, list_func 
							in  self.funcs.items() 
							if  func_name in list_func)
						) 
					)

				if (self.calc_hash_func_name and self.calc_hash_dll_name):
					yield (hash_val, key_value)

				if (self.calc_hash_dll_name and not self.calc_hash_func_name):
					dll_name = self.hash_dict[hash_val]
					yield (hash_val, dll_name)
			except:
				yield (None, None)


def split_array_into_tuples(arr, n):
    if  n == 0:
        n = len(arr) // 3 if len(arr) >= 3 else len(arr)
    return [tuple(arr[i:i+n]) for i in range(0, len(arr), n)]


