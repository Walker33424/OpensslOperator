import tkinter.ttk as ttk
import os
import threading as t
import subprocess as s
import tkinter as tk
from tkinter import messagebox as m
from tkinter import filedialog


class OpensslRSAOperator:
    """
        GUI Openssl operator
    """

    def __init__(self):
        self.path = "temp"
        self.ramdisk = True
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
        self.tk.geometry("960x460")
        self.operations_box = tk.Text(self.tk, height=15, width=30)
        self.operations = []
        self.save_file_path = ""
        self.text = tk.Text(self.tk, height=15, width=30)
        self.private_path = tk.Label(self.tk, text="Private key:")
        self.public_path = tk.Label(self.tk, text="Public key:")
        self.public_path.place(x=260, y=115)
        self.pub = False
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
        self.tk.mainloop()

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

    def create_ramdisk(self):
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

    def execute_encryption(self, file, file_output, pub=False):
        if pub:
            pub = "-pubin"
            key_path = self._public_key_path
        else:
            pub = ""
            key_path = self._private_key_path
        try:
            report = s.check_output(
                "openssl pkeyutl -encrypt -in " + file + pub + "-inkey" + key_path +
                "-out " + file_output)
            print(report.decode())
        except s.SubprocessError as error_data:
            print(repr(s.SubprocessError), str(error_data))

    def execute_decryption(self, file, file_output, pub=False):
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
            operation = "Encrypt"
        elif operation is False:
            operation = "Decrypt"
        paths = filedialog.askopenfilenames(title="Choose files to " + operation,
                                            initialdir=(os.path.expanduser(default_dir)))
        self.operations.append([operation, paths])

    def file_split(self):
        file_range = 0
        over_flag = False
        file_output = open(self.file_output, "w+")
        size_sum = 0
        if self.ramdisk:
            self.path = "/mnt/ramdisk/temp"
        else:
            self.path = "temp"
        file = open(self.file, "ra")
        if self.operation == "No operation":
            m.showerror("Error", "No operation to do.")
        elif self.operation == "encrypt":
            while True:
                if (size_sum >= 10485000 and self.ramdisk) or over_flag:
                    for x in range(0, file_range + 1):
                        file_output.write(open(self.path + str(x)).read() + "<fi-seq>")
                        os.remove(self.path + str(x))
                    file_range, size_sum = 0, 0
                    file_output.flush()
                data = file.read(500)
                if not data:
                    over_flag = True
                    continue
                file_temp = open(self.path + str(file_range), "w+")
                file_temp.write(data)
                self.execute_encryption(self.path, file_output=self.path + str(file_range), pub=self.pub)
                size_sum += 500
        elif self.operation == "decrypt":
            file.read(1016)
            
        else:
            m.showerror("Error", "Unknown operation")


def main():
    operator = OpensslRSAOperator()
    print(operator)
    del operator


if __name__ == '__main__':
    main()
