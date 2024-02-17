import tkinter as tk
from tkinter import filedialog, messagebox
import zipfile
import itertools
import threading
import colorama
from colorama import Fore
import time

colorama.init()

stop_thread = False

def extract_zip(file_path, password):
    try:
        with zipfile.ZipFile(file_path) as zf:
            zf.extractall(pwd=password.encode())
        print(Fore.GREEN + f"Password Found: {password}")
        messagebox.showinfo("Success", f"Password Found: {password}")
        return True
    except Exception as e:
        print(Fore.RED + f"Not Password: {password}")
        return False

def brute_force_attack(file_path, max_length, include_numbers):
    global stop_thread
    characters = ''
    if include_numbers:
        characters += '0123456789'
    else:
        characters += 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!@#$%^&*()-_+=~`[]{}|;:,.<>?'
        
    total_combinations = sum(len(characters) ** length for length in range(1, max_length + 1))
    print(f"Total combinations: {total_combinations}")
    start_time = time.time()
    tried_combinations = 0
    
    for length in range(1, max_length + 1):
        if stop_thread:
            break
        for password in itertools.product(characters, repeat=length):
            if stop_thread:
                break
            password_str = ''.join(password)
            if extract_zip(file_path, password_str):
                return True
            
            tried_combinations += 1
            if tried_combinations % 1000 == 0:  # 매 1000번마다 예상 시간 업데이트
                update_time_label(start_time, tried_combinations, total_combinations)
    
    end_time = time.time()
    elapsed_time = end_time - start_time
    print(f"Elapsed time: {elapsed_time:.2f} seconds")

def update_time_label(start_time, tried_combinations, total_combinations):
    if tried_combinations == 0:
        return  # 시도된 비밀번호가 없을 때는 작업 예상 시간을 업데이트하지 않음
    
    elapsed_time = time.time() - start_time
    remaining_combinations = total_combinations - tried_combinations
    time_per_combination = elapsed_time / tried_combinations
    estimated_time_remaining = time_per_combination * remaining_combinations

    if estimated_time_remaining < 600:
        time_label.config(text=f"Estimated Time Remaining: {estimated_time_remaining:.2f} seconds", fg="green")
    elif estimated_time_remaining < 3600:
        time_label.config(text=f"Estimated Time Remaining: {estimated_time_remaining / 60:.2f} minutes", fg="orange")
    elif estimated_time_remaining < 86400:
        time_label.config(text=f"Estimated Time Remaining: {estimated_time_remaining / 3600:.2f} hours", fg="red")
    elif estimated_time_remaining < 360000:
        time_label.config(text="Estimated Time Remaining: Calculating...", fg="black")
    else:
        time_label.config(text="Estimated Time Remaining: 10000Hours Error", fg="red")

def start_attack():
    global stop_thread
    stop_thread = False
    file_path = file_entry.get()
    max_length = int(max_length_entry.get())
    include_numbers = include_numbers_var.get()
    if file_path:
        thread = threading.Thread(target=brute_force_attack, args=(file_path, max_length, include_numbers))
        thread.start()

def stop_attack():
    global stop_thread
    stop_thread = True

# GUI 생성
root = tk.Tk()
root.title("zip파일 password 해독기")

# 파일 선택 창
file_label = tk.Label(root, text="Select Zip File:")
file_label.pack(padx=20, pady=(20, 5))

file_entry = tk.Entry(root, width=40)
file_entry.pack(padx=20, pady=5)

file_button = tk.Button(root, text="Browse", command=lambda: file_entry.insert(tk.END, filedialog.askopenfilename(filetypes=[("ZIP files", "*.zip")])))
file_button.pack(padx=20, pady=5)

# 최대 비밀번호 길이 입력
max_length_label = tk.Label(root, text="Max Password Length:")
max_length_label.pack(padx=20, pady=(0, 5))

max_length_entry = tk.Entry(root)
max_length_entry.pack(padx=20, pady=5)
max_length_entry.insert(0, "8")  # 기본값으로 8 설정

# 숫자 포함 체크박스
include_numbers_var = tk.BooleanVar()
include_numbers_var.set(False)  # 기본값은 False로 설정
include_numbers_check = tk.Checkbutton(root, text="Include Numbers", variable=include_numbers_var)
include_numbers_check.pack(padx=20, pady=5)

# 시작 버튼
start_button = tk.Button(root, text="Start", command=start_attack)
start_button.pack(padx=20, pady=10)

# 중지 버튼
stop_button = tk.Button(root, text="Stop", command=stop_attack)
stop_button.pack(padx=20, pady=5)

# 작업 예상 시간 표시 레이블
time_label = tk.Label(root, text="Estimated Time Remaining: ", fg="black")
time_label.pack(padx=20, pady=5)

root.mainloop()
