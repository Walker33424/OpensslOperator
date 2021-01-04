import tkinter.ttk as ttk
import os
import threading as t
import subprocess as s
import tkinter as tk
from tkinter import messagebox as m
from tkinter import filedialog


# 未完成：加解密逻辑需要进一步实现
class OpensslRSAOperator:
    """
        GUI Openssl operator
    """

    def __init__(self):
        self.path = "temp"
        self.ramdisk = False
        self.SUPPORTED_RSA_KEY_SIZE = 4096
        self.MAX_FILE_SIZE = 500
        self.tk = tk.Tk()
        self.file_output = ""
        tk.Label(self.tk, text="""The program will read and write data to the disk at high speed
\nIf you want the program to run faster, or you want to avoid reducing the life of USB flash disk\n and other devices \
due to fast reading and writing\nclick the "Use Ramdisk(10MB)" button to create a memory disk (10MB)""") \
            .place(x=420, y=0)
        self.create = ttk.Button(self.tk, text="Use Ramdisk(10MB)", command=self.create_ramdisk)
        self.create.place(x=130, y=0)
        self.tk.title("Openssl Operator")
        tk.Label(self.tk, text="If you want to encrypt shorter data\nwrite it here").place(x=0, y=60)
        self.file = ""
        self.tk.geometry("1300x460")
        self.operations_box = tk.Text(self.tk, height=15, width=75)
        self.file_lock = t.Lock()
        self.add_operation_button = ttk.Button(self.tk, command=self.add_operation, text="Add a operation")
        self.add_operation_button.place(x=250, y=195)
        self.tf_lock = t.Lock()
        self.operations = []
        self.delete_entry = ttk.Entry(self.tk)
        self.delete_entry.place(x=550, y=150)
        self.delete_button = ttk.Button(self.tk, text="Delete operation", command=self.delete_operation)
        self.delete_button.place(x=730, y=145)
        self.key_type = True
        self.save_file_path = ""
        # self.choose_file_output = ttk.Button(self.tk, command=self.choose_file_output,
        #                                      text="Choose a file save route to output")
        # self.choose_file_output.place(x=250, y=65)
        self.encrypt_text = ttk.Button(self.tk, command=self.encrypt_short_data, text="Encrypt Data From Textbox")
        self.encrypt_text.place(x=250, y=165)
        self.text = tk.Text(self.tk, height=15, width=30)
        self.operations_box.place(x=500, y=175)
        self.file_label = tk.Label(self.tk, text="File:")
        self.file_label.place(x=260, y=135)
        self.private_path = tk.Label(self.tk, text="Private key:")
        self.public_path = tk.Label(self.tk, text="Public key:")
        self.public_path.place(x=260, y=115)
        self.pub = False
        # 注:下面这个变量是给解密线程用的
        self.file_output_object = None
        self.private_path.place(x=260, y=95)
        self.operation = "No operate"
        self.text.place(x=0, y=95)
        tk.Label(self.tk, text="Openssl Operator").place(x=0, y=0)
        self.private_key = ttk.Button(self.tk, text="Choose a private key", command=self._private_key_choose)
        self.public_key = ttk.Button(self.tk, text="Or a public key", command=self._public_key_choose)
        self.public_key.place(x=210, y=30)
        self.private_key.place(x=0, y=30)
        self._private_key_path = None
        self._public_key_path = ""
        self.run_operations = ttk.Button(self.tk, command=self.run_all, text="Run all operations")
        self.run_operations.place(x=1000, y=0)
        self.tk.mainloop()

    # def choose_file_output(self):
    #     self.file_output = filedialog.asksaveasfilename(title="Choose a file to output",
    #                                                     initialdir=(os.path.expanduser(r"")))
    #     self.file_label["text"] = "File output:" + self.file_output
    #     self.choose_file_output["text"] = "Save file to another place"

    def delete_operation(self):
        self.delete_button["text"] = "Deleting..."
        try:
            self.operations.pop(int(self.delete_entry.get()) - 1)
        except ValueError:
            m.showerror("ERROR", "Not a number!")
            return
        self.operations_box.delete(1.0, "end")
        file_sum = 0
        for x in self.operations:
            file_sum += 1
            self.operations_box.insert("insert", "###->Operation{}: {} {}, output: {}\n".format(
                file_sum, x[0].title(), x[1], x[2]))
        self.delete_button["text"] = "Delete operation"

    # def create_file_output(self):
    #     self.file_output_object = open(self.file_output)

    def encrypt_short_data(self):
        pass

    def _public_key_choose(self):
        default_dir = r""
        self._public_key_path = filedialog.askopenfilename(title="Choose a public key file",
                                                           initialdir=(os.path.expanduser(default_dir)))
        self.public_key["text"] = "Change to another public key"
        self.public_path["text"] = "Public key:" + self._public_key_path

    def _private_key_choose(self):
        default_dir = r""
        self._private_key_path = filedialog.askopenfilename(title="Choose a private key file",
                                                            initialdir=(os.path.expanduser(default_dir)))
        self.private_key["text"] = "Change to another private key"
        self.private_path["text"] = "Private key:" + self._private_key_path

    def create_ramdisk(self) -> None:
        command = """mkdir -p /mnt/ramdisk&&chown root:root /mnt/ramdisk&&mount -t tmpfs -o size=10M tmpfs 
        /mnt/ramdisk """
        st = m.askyesno("Question", "Are you sure you want to create a ramdisk?")
        print(st)
        if st:
            self.create["text"] = "Creating Ramdisk..."
            try:
                output = s.check_output(command, shell=True)
                print(output)
                self.ramdisk = True
                self.create["text"] = "Create Ramdisk Successfully"
            except s.SubprocessError:
                m.showerror("Error", "Cannot create ramdisk on /mnt/ramdisk, please create it yourself")
                self.ramdisk = False
                self.create["text"] = "Create Ramdisk Failed"

    def execute_encryption(self, file, file_output, pub=False) -> None:
        if pub:
            pub = "-pubin"
            key_path = self._public_key_path
        else:
            pub = ""
            key_path = self._private_key_path
        try:
            report = s.check_output(
                "openssl pkeyutl -encrypt -in " + file + pub + "-inkey" + key_path +
                "-out " + file_output, shell=True)
            print(report.decode())
        except s.SubprocessError as error_data:
            print(repr(s.SubprocessError), str(error_data))
        except TypeError:
            m.showerror("ERROR", "No key!")

    def execute_decryption(self, file, file_output, pub=False) -> None:
        if pub:
            pub = "-pubin"
            key_path = self._public_key_path
        else:
            pub = ""
            key_path = self._private_key_path
        try:
            report = s.check_output("openssl pkeyutl -decrypt -in " + file + " -inkey" + pub +
                                    key_path + "-out " + file_output)
            print(report)
        except s.SubprocessError as error_data:
            print(repr(s.SubprocessError), str(error_data))

    def add_operation(self):
        default_dir = r""
        operation = m.askyesnocancel("Which type of operation?",
                                     "For encryption, click Yes\nFor decryption, click No")
        if operation is None:
            return
        elif operation:
            operation = "encrypt"
        elif operation is False:
            operation = "decrypt"
        key_type = m.askyesnocancel("Which type of key?",
                                    "For Private key, click Yes\nFor Public key, click No")
        if key_type is None:
            return
        elif key_type:
            key_type = False
        elif key_type is False:
            key_type = True
        path = filedialog.askopenfilename(title="Choose files to " + operation,
                                          initialdir=(os.path.expanduser(default_dir)))
        if path == "":
            return
        save_path = filedialog.asksaveasfilename(title="Choose a route to output",
                                                 initialdir=(os.path.expanduser(default_dir)))
        if save_path == "":
            return
        self.operations.append([operation, path, save_path, key_type])
        self.operations_box.insert("insert", "###->Operation{}: {} {}, output: {}, Use private key:{}\n".format(
            str(len(self.operations)), operation.title(), path, save_path, str(key_type)))

    def sub_thread(self, file_label, data, is_main):
        # Decrypt data with main thread
        if is_main:
            self.file_lock.acquire()
            self.tf_lock.release()
            self.file_lock.acquire()
        fp = self.path + str(file_label)
        file = open(fp, "w+")
        file.write(data)
        file.close()
        self.execute_decryption(fp, fp, not self.key_type)
        if not is_main:
            self.file_lock.acquire()
        self.file_output_object.write(open(fp).read())
        self.file_lock.release()
        return

    def run_all(self):
        file_sum = 0
        response = m.askyesno("Question", "Are you sure you want to run these operations now?")
        if not response:
            return
        if not self.operations:
            m.showerror("Error", "No operation to do.")
        for x in self.operations:
            file_sum += 1
            self.run_operations["text"] = "Running...Operation" + str(file_sum)
            self.file = x[1]
            self.file_output = x[2]
            self.file_split(x[0])
            self.key_type = x[3]
        m.showinfo("INFO", "Success")
        self.run_operations["text"] = "Run all operations"
        self.operations_box.delete(1.0, "end")
        self.operations.clear()

    def file_split(self, operation):
        file_range = 0
        over_flag = False
        file_output = open(self.file_output, "w+")
        size_sum = 0
        if self.ramdisk:
            self.path = "/mnt/ramdisk/temp"
        else:
            self.path = "temp"
        file = open(self.file, "rb")
        if operation == "encrypt":
            while True:
                if size_sum >= 10485000 or over_flag:
                    for x in range(1, file_range + 1):
                        try:
                            file_output.write(open(self.path + str(x)).read())
                            os.remove(self.path + str(x))
                        except FileNotFoundError:
                            pass
                    file_range, size_sum = 0, 0
                    file_output.flush()
                    if over_flag:
                        return
                data = file.read(500)
                if file_range == 24:
                    print(data)
                if data == "":
                    over_flag = True
                    continue
                else:
                    file_range += 1
                file_temp = open(self.path + str(file_range), "wb")
                file_temp.write(data)
                self.execute_encryption(self.path, file_output=self.path + str(file_range), pub=not self.key_type)
                size_sum += 500
        elif operation == "decrypt":
            file_label = 0
            while True:
                self.tf_lock.acquire()
                data = file.read(1000)
                if not data:
                    self.file_output_object.close()
                    return
                fd = [data[0:501], data[501:1001]]
                self.sub_thread(file_label, fd[0], True)
                self.tf_lock.acquire()
                t.Thread(target=self.sub_thread, args=(file_label + 1, fd[1], False))

        else:
            m.showerror("Error", "Unknown operation")


def main():
    operator = OpensslRSAOperator()
    print(operator)
    del operator


if __name__ == '__main__':
    main()
