import ctypes
import pymem
import time
import re
import os
import psutil
import webview
import base64
import tkinter as tk
from tkinter import ttk, messagebox

windll = ctypes.windll

os.system("cls" if os.name == "nt" else "clear")

RED = "\033[91m"
PURPLE = "\033[35m"
RESET = "\033[0m"

childrenOffset = 0
parentOffset = 0

ctypes.windll.kernel32.SetConsoleTitleW("vyxa was here :3")


class ExplorerUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Explorer")
        self.root.geometry("800x600")
        frame = ttk.Frame(root)
        frame.pack(fill="both", expand=True)
        self.tree = ttk.Treeview(frame, selectmode="browse")
        self.tree.heading("#0", text="Explorer", anchor="w")
        self.tree.pack(side="left", fill="both", expand=True)
        scrollbar = ttk.Scrollbar(frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)
        scrollbar.pack(side="right", fill="y")
        self.tree.bind("<Button-3>", self.show_context_menu)
        self.context_menu = tk.Menu(root, tearoff=0)
        self.context_menu.add_command(label="Show Address", command=self.show_address)
        self.context_menu.add_command(label="Copy Address", command=self.copy_address)
        self.node_addresses = {}

    def add_children(self, parent_id, parent_instance):
        children = parent_instance.GetChildren()
        for child in children:
            if child:
                child_id = self.tree.insert(
                    parent_id, "end", text=child.Name, open=False
                )
                self.node_addresses[child_id] = child.Address
                self.add_children(child_id, child)

    def populate(self, game):
        game_id = self.tree.insert("", "end", text="Game", open=True)
        self.node_addresses[game_id] = game.Address
        self.add_children(game_id, game)

    def show_context_menu(self, event):
        selected_item = self.tree.identify_row(event.y)
        if selected_item:
            self.tree.selection_set(selected_item)
            self.context_menu.post(event.x_root, event.y_root)

    def show_address(self):
        selected_item = self.tree.selection()
        if selected_item:
            address = self.node_addresses.get(selected_item[0], "Unknown")
            messagebox.showinfo("Address", f"Memory Address: {hex(address)}")

    def copy_address(self):
        selected_item = self.tree.selection()
        if selected_item:
            address = self.node_addresses.get(selected_item[0], "Unknown")
            self.root.clipboard_clear()
            self.root.clipboard_append(hex(address))
            self.root.update_idletasks()
            messagebox.showinfo(
                "Copied", f"Address {hex(address)} copied to clipboard."
            )


class Redeemer:
    def __init__(self, program_name):
        self.program_name = program_name

    def SimpleGetProcesses(self):
        return [proc.name() for proc in psutil.process_iter(["name"])]

    def SetParent(self, Instance, Parent, parentOffset):
        Redeemer.Pymem.write_longlong(Instance + parentOffset, Parent)

    def __init__(self, ProgramName=None):
        self.ProgramName = ProgramName
        self.Pymem = pymem.Pymem()
        self.Addresses = {}
        self.Handle = None
        self.is64bit = True
        self.ProcessID = None
        self.PID = self.ProcessID
        if type(ProgramName) == str:
            self.Pymem = pymem.Pymem(ProgramName)
            self.Handle = self.Pymem.process_handle
            self.is64bit = pymem.process.is_64_bit(self.Handle)
            self.ProcessID = self.Pymem.process_id
            self.PID = self.ProcessID
        elif type(ProgramName) == int:
            self.Pymem.open_process_from_id(ProgramName)
            self.Handle = self.Pymem.process_handle
            self.is64bit = pymem.process.is_64_bit(self.Handle)
            self.ProcessID = self.Pymem.process_id
            self.PID = self.ProcessID

    def h2d(self, hz: str, bit: int = 16) -> int:
        if type(hz) == int:
            return hz
        return int(hz, bit)

    def d2h(self, dc: int, UseAuto=None) -> str:
        if type(dc) == str:
            return dc
        if UseAuto:
            if UseAuto == 32:
                dc = hex(dc & (2**32 - 1)).replace("0x", "")
            else:
                dc = hex(dc & (2**64 - 1)).replace("0x", "")
        else:
            if abs(dc) > 4294967295:
                dc = hex(dc & (2**64 - 1)).replace("0x", "")
            else:
                dc = hex(dc & (2**32 - 1)).replace("0x", "")
        if len(dc) > 8:
            while len(dc) < 16:
                dc = "0" + dc
        if len(dc) < 8:
            while len(dc) < 8:
                dc = "0" + dc
        return dc

    def PLAT(self, aob: str):
        if type(aob) == bytes:
            return aob
        trueB = bytearray(b"")
        aob = aob.replace(" ", "")
        PLATlist = []
        for i in range(0, len(aob), 2):
            PLATlist.append(aob[i : i + 2])
        for i in PLATlist:
            if "?" in i:
                trueB.extend(b".")
            if "?" not in i:
                trueB.extend(re.escape(bytes.fromhex(i)))
        return bytes(trueB)

    def AOBSCANALL(self, AOB_HexArray, xreturn_multiple=False):
        return pymem.pattern.pattern_scan_all(
            self.Pymem.process_handle,
            self.PLAT(AOB_HexArray),
            return_multiple=xreturn_multiple,
        )

    def gethexc(self, hex: str):
        hex = hex.replace(" ", "")
        hxlist = []
        for i in range(0, len(hex), 2):
            hxlist.append(hex[i : i + 2])
        return len(hxlist)

    def hex2le(self, hex: str):
        lehex = hex.replace(" ", "")
        lelist = []
        if len(lehex) > 8:
            while len(lehex) < 16:
                lehex = "0" + lehex
            for i in range(0, len(lehex), 2):
                lelist.append(lehex[i : i + 2])
            lelist.reverse()
            return "".join(lelist)
        if len(lehex) < 9:
            while len(lehex) < 8:
                lehex = "0" + lehex
            for i in range(0, len(lehex), 2):
                lelist.append(lehex[i : i + 2])
            lelist.reverse()
            return "".join(lelist)

    def calcjmpop(self, des, cur):
        jmpopc = (self.h2d(des) - self.h2d(cur)) - 5
        jmpopc = hex(jmpopc & (2**32 - 1)).replace("0x", "")
        if len(jmpopc) % 2 != 0:
            jmpopc = "0" + str(jmpopc)
        return jmpopc

    def isProgramGameActive(self):
        try:
            self.Pymem.read_char(self.Pymem.base_address)
            return True
        except:
            return False

    def DRP(self, Address: int, is64Bit: bool = None) -> int:
        Address = Address
        if type(Address) == str:
            Address = self.h2d(Address)
        if is64Bit:
            return int.from_bytes(self.Pymem.read_bytes(Address, 8), "little")
        if self.is64bit:
            return int.from_bytes(self.Pymem.read_bytes(Address, 8), "little")
        return int.from_bytes(self.Pymem.read_bytes(Address, 4), "little")

    def isValidPointer(self, Address: int, is64Bit: bool = None) -> bool:
        try:
            if type(Address) == str:
                Address = self.h2d(Address)
            self.Pymem.read_bytes(self.DRP(Address, is64Bit), 1)
            return True
        except:
            return False

    def GetModules(self) -> list:
        return list(self.Pymem.list_modules())

    def getAddressFromName(self, Address: str) -> int:
        if type(Address) == int:
            return Address
        AddressBase = 0
        AddressOffset = 0
        for i in self.GetModules():
            if i.name in Address:
                AddressBase = i.lpBaseOfDll
                AddressOffset = self.h2d(Address.replace(i.name + "+", ""))
                AddressNamed = AddressBase + AddressOffset
                return AddressNamed
        print("\033[91mAdress failed: \033[0m" + Address)
        return Address

    def getNameFromAddress(self, Address: int) -> str:
        memoryInfo = pymem.memory.virtual_query(self.Pymem.process_handle, Address)
        BaseAddress = memoryInfo.BaseAddress
        NameOfDLL = ""
        AddressOffset = 0
        for i in self.GetModules():
            if i.lpBaseOfDll == BaseAddress:
                NameOfDLL = i.name
                AddressOffset = Address - BaseAddress
                break
        if NameOfDLL == "":
            return Address
        NameOfAddress = NameOfDLL + "+" + self.d2h(AddressOffset)
        return NameOfAddress

    def getRawProcesses(self):
        toreturn = []
        for i in pymem.process.list_processes():
            toreturn.append(
                [
                    i.cntThreads,
                    i.cntUsage,
                    i.dwFlags,
                    i.dwSize,
                    i.pcPriClassBase,
                    i.szExeFile,
                    i.th32DefaultHeapID,
                    i.th32ModuleID,
                    i.th32ParentProcessID,
                    i.th32ProcessID,
                ]
            )
        return toreturn

    def SimpleGetProcesses(self):
        toreturn = []
        for i in self.getRawProcesses():
            toreturn.append({"Name": i[5].decode(), "Threads": i[0], "ProcessId": i[9]})
        return toreturn

    def YieldForProgram(self, programName, AutoOpen: bool = False, Limit=15):
        Count = 0
        while True:
            if Count > Limit:
                print("\033[91mProgram timed out\033[0m")
                return False
            ProcessesList = self.SimpleGetProcesses()
            for i in ProcessesList:
                if i["Name"] == programName:

                    if AutoOpen:
                        self.Pymem.open_process_from_id(i["ProcessId"])
                        self.ProgramName = programName
                        self.Handle = self.Pymem.process_handle
                        self.is64bit = pymem.process.is_64_bit(self.Handle)
                        self.ProcessID = self.Pymem.process_id
                        self.PID = self.ProcessID
                    return True
            time.sleep(1)
            Count += 1

    def ReadPointer(
        self, BaseAddress: int, Offsets_L2R: list, is64Bit: bool = None
    ) -> int:
        x = self.DRP(BaseAddress, is64Bit)
        y = Offsets_L2R
        z = x
        if y == None or len(y) == 0:
            return z
        count = 0
        for i in y:
            try:
                print(self.d2h(x + i))
                print(self.d2h(i))
                z = self.DRP(z + i, is64Bit)
                count += 1
                print(self.d2h(z))
            except:
                print("\033[91mNo index offset: \033[0m" + str(count))
                return z
        return z

    def GetMemoryInfo(self, Address: int, Handle: int = None):
        if Handle:
            return pymem.memory.virtual_query(Handle, Address)
        else:
            return pymem.memory.virtual_query(self.Handle, Address)

    def MemoryInfoToDictionary(self, MemoryInfo):
        return {
            "BaseAddress": MemoryInfo.BaseAddress,
            "AllocationBase": MemoryInfo.AllocationBase,
            "AllocationProtect": MemoryInfo.AllocationProtect,
            "RegionSize": MemoryInfo.RegionSize,
            "State": MemoryInfo.State,
            "Protect": MemoryInfo.Protect,
            "Type": MemoryInfo.Type,
        }

    def SetProtection(
        self,
        Address: int,
        ProtectionType=0x40,
        Size: int = 4,
        OldProtect=ctypes.c_ulong(0),
    ):
        pymem.ressources.kernel32.VirtualProtectEx(
            self.Pymem.process_handle,
            Address,
            Size,
            ProtectionType,
            ctypes.byref(OldProtect),
        )
        return OldProtect

    def ChangeProtection(
        self,
        Address: int,
        ProtectionType=0x40,
        Size: int = 4,
        OldProtect=ctypes.c_ulong(0),
    ):
        return self.SetProtection(Address, ProtectionType, Size, OldProtect)

    def GetProtection(self, Address: int):
        return self.GetMemoryInfo(Address).Protect

    def KnowProtection(self, Protection):
        if Protection == 0x10:
            return "PAGE_EXECUTE"
        if Protection == 0x20:
            return "PAGE_EXECUTE_READ"
        if Protection == 0x40:
            return "PAGE_EXECUTE_READWRITE"
        if Protection == 0x80:
            return "PAGE_EXECUTE_WRITECOPY"
        if Protection == 0x01:
            return "PAGE_NOACCESS"
        if Protection == 0x02:
            return "PAGE_READONLY"
        if Protection == 0x04:
            return "PAGE_READWRITE"
        if Protection == 0x08:
            return "PAGE_WRITECOPY"
        if Protection == 0x100:
            return "PAGE_GUARD"
        if Protection == 0x200:
            return "PAGE_NOCACHE"
        if Protection == 0x400:
            return "PAGE_WRITECOMBINE"
        if Protection in ["PAGE_EXECUTE", "execute", "e"]:
            return 0x10
        if Protection in [
            "PAGE_EXECUTE_READ",
            "execute read",
            "read execute",
            "execute_read",
            "read_execute",
            "er",
            "re",
        ]:
            return 0x20
        if Protection in [
            "PAGE_EXECUTE_READWRITE",
            "execute read write",
            "execute write read",
            "write execute read",
            "write read execute",
            "read write execute",
            "read execute write",
            "erw",
            "ewr",
            "wre",
            "wer",
            "rew",
            "rwe",
        ]:
            return 0x40
        if Protection in [
            "PAGE_EXECUTE_WRITECOPY",
            "execute copy write",
            "execute write copy",
            "write execute copy",
            "write copy execute",
            "copy write execute",
            "copy execute write",
            "ecw",
            "ewc",
            "wce",
            "wec",
            "cew",
            "cwe",
        ]:
            return 0x80
        if Protection in ["PAGE_NOACCESS", "noaccess", "na", "n"]:
            return 0x01
        if Protection in ["PAGE_READONLY", "readonly", "ro", "r"]:
            return 0x02
        if Protection in ["PAGE_READWRITE", "read write", "write read", "wr", "rw"]:
            return 0x04
        if Protection in ["PAGE_WRITECOPY", "write copy", "copy write", "wc", "cw"]:
            return 0x08
        if Protection in ["PAGE_GUARD", "pg", "guard", "g"]:
            return 0x100
        if Protection in ["PAGE_NOCACHE", "nc", "nocache"]:
            return 0x200
        if Protection in ["PAGE_WRITECOMBINE", "write combine", "combine write"]:
            return 0x400
        return Protection

    def Suspend(self, pid: int = None):
        kernel32 = ctypes.WinDLL("kernel32.dll")
        if pid:
            kernel32.DebugActiveProcess(pid)
        if self.PID:
            kernel32.DebugActiveProcess(self.PID)

    def Resume(self, pid: int = None):
        kernel32 = ctypes.WinDLL("kernel32.dll")
        if pid:
            kernel32.DebugActiveProcessStop(pid)
        if self.PID:
            kernel32.DebugActiveProcessStop(self.PID)


Redeemer = Redeemer()

print("Waiting for roblox")
while True:
    if Redeemer.YieldForProgram("RobloxPlayerBeta.exe", True, 15):
        break
print("Found Roblox")


def GetViewRegex(folderPath, latestFile):
    filePath = folderPath + "\\" + latestFile
    regexPattern = re.compile(r"view\((\w+)\)")
    try:
        with open(filePath, "r", encoding="utf-8") as fileStream:
            for line in fileStream:
                match = regexPattern.search(line)
                if match:
                    newAddress = int(match.group(1), 16)
                    return newAddress
    except IOError:
        print(f"Failed to open file: {filePath}")
        return 0


def readQword(process, address, value):
    try:
        value.value = process.read_ulonglong(address)
        return True
    except pymem.exception.MemoryReadError:

        exit()


def GetLatestFile(folderPath, file_filter=None):
    try:
        files = [
            f
            for f in os.listdir(folderPath)
            if os.path.isfile(os.path.join(folderPath, f))
        ]
        if file_filter:
            files = [f for f in files if file_filter in f]
        latest_file = max(
            files, key=lambda f: os.path.getmtime(os.path.join(folderPath, f))
        )
        return latest_file
    except Exception as e:
        print("Error:", e)
        return None


def GetDataModel():
    localAppData = os.environ.get("LOCALAPPDATA")
    if localAppData:
        folderPath = os.path.join(os.getenv("LOCALAPPDATA"), "Roblox", "logs")
        latestFile = GetLatestFile(folderPath, "Player")
        process = pymem.Pymem("RobloxPlayerBeta.exe")
        RenderView = GetViewRegex(folderPath, latestFile)
        if RenderView:
            RandomAssShitlmao = ctypes.c_ulonglong(0)
            try:
                readQword(process, RenderView + 0x118, RandomAssShitlmao)
            except Exception as e:
                print(e)
            DataModel = ctypes.c_ulonglong(0)
            if readQword(process, RandomAssShitlmao.value + 0x1A8, DataModel):
                game = DataModel.value
                return game
            else:
                return None


def ClearDetection():
    for file in os.listdir(f"C:/Users/{os.getlogin()}/AppData/Local/Roblox/logs"):
        try:
            os.remove(f"C:/Users/{os.getlogin()}/AppData/Local/Roblox/logs/" + file)
        except:
            pass


def ReadRobloxString(ExpectedAddress: int) -> str:
    StringCount = Redeemer.Pymem.read_int(ExpectedAddress + 0x10)
    if StringCount > 15:
        return Redeemer.Pymem.read_string(Redeemer.DRP(ExpectedAddress), StringCount)
    return Redeemer.Pymem.read_string(ExpectedAddress, StringCount)


def GetClassName(Instance: int) -> str:
    ExpectedAddress = Redeemer.DRP(Redeemer.DRP(Instance + 0x18) + 8)
    return ReadRobloxString(ExpectedAddress)


def setParent(Instance, Parent, parentOffset, childrenOffset):
    InjectorClass = Redeemer
    InjectorClass.Pymem.write_longlong(Instance + parentOffset, Parent)
    newChildren = InjectorClass.Pymem.allocate(0x400)
    InjectorClass.Pymem.write_longlong(newChildren + 0, newChildren + 0x40)
    ptr = InjectorClass.Pymem.read_longlong(Parent + childrenOffset)
    childrenStart = InjectorClass.Pymem.read_longlong(ptr)
    childrenEnd = InjectorClass.Pymem.read_longlong(ptr + 8)
    if childrenStart == 0 or childrenEnd == 0 or childrenEnd <= childrenStart:
        exit()
    length = childrenEnd - childrenStart
    if length < 0:
        exit()
    b = InjectorClass.Pymem.read_bytes(childrenStart, length)
    InjectorClass.Pymem.write_bytes(newChildren + 0x40, b, len(b))
    e = newChildren + 0x40 + length
    InjectorClass.Pymem.write_longlong(e, Instance)
    InjectorClass.Pymem.write_longlong(
        e + 8, InjectorClass.Pymem.read_longlong(Instance + 0x10)
    )
    e = e + 0x10
    InjectorClass.Pymem.write_longlong(newChildren + 0x8, e)
    InjectorClass.Pymem.write_longlong(newChildren + 0x10, e)


def inject():
    try:
        PROCNAME = "RobloxCrashHandler.exe"

        for proc in psutil.process_iter():
            if proc.name() == PROCNAME:
                proc.kill()

        nameOffset = 0x68
        childrenOffset = 0x70
        parentOffset = 0x50

        def GetNameAddress(Instance: int) -> int:
            ExpectedAddress = Redeemer.DRP(Instance + nameOffset, True)
            return ExpectedAddress

        def GetName(Instance: int) -> str:
            ExpectedAddress = GetNameAddress(Instance)
            return ReadRobloxString(ExpectedAddress)

        def GetChildren(Instance: int) -> str:
            ChildrenInstance = []
            InstanceAddress = Instance
            if not InstanceAddress:
                return False
            ChildrenStart = Redeemer.DRP(InstanceAddress + childrenOffset, True)
            if ChildrenStart == 0:
                return []
            ChildrenEnd = Redeemer.DRP(ChildrenStart + 8, True)
            OffsetAddressPerChild = 0x10
            CurrentChildAddress = Redeemer.DRP(ChildrenStart, True)
            for i in range(0, 9000):
                if CurrentChildAddress == ChildrenEnd:
                    break
                ChildrenInstance.append(
                    Redeemer.Pymem.read_longlong(CurrentChildAddress)
                )
                CurrentChildAddress += OffsetAddressPerChild
            return ChildrenInstance

        def GetParent(Instance: int) -> int:
            return Redeemer.DRP(Instance + parentOffset, True)

        def FindFirstChildW(Instance: int, ChildName: str) -> int:
            ChildrenOfInstance = GetChildren(Instance)
            for i in ChildrenOfInstance:
                if GetName(i) == ChildName:
                    return i

        def FindFirstChildOfClass(Instance: int, ClassName: str) -> int:
            ChildrenOfInstance = GetChildren(Instance)
            for i in ChildrenOfInstance:
                if GetClassName(i) == ClassName:
                    return i

        class toInstance:
            def __init__(self, address: int = 0):
                self.Address = address
                self.Self = address
                self.Name = GetName(address)
                self.ClassName = GetClassName(address)
                self.Parent = GetParent(address)

            def setParent(self, Parent):
                setParent(self.Address, Parent)

            def GetChildren(self):
                ChildrenInstance = []
                InstanceAddress = self.Address
                if not InstanceAddress:
                    return False
                ChildrenStart = Redeemer.DRP(InstanceAddress + childrenOffset, True)
                if ChildrenStart == 0:
                    return []
                ChildrenEnd = Redeemer.DRP(ChildrenStart + 8, True)
                OffsetAddressPerChild = 0x10
                CurrentChildAddress = Redeemer.DRP(ChildrenStart, True)
                for i in range(0, 9000):
                    if CurrentChildAddress == ChildrenEnd:
                        break
                    ChildrenInstance.append(
                        toInstance(Redeemer.Pymem.read_longlong(CurrentChildAddress))
                    )
                    CurrentChildAddress += OffsetAddressPerChild
                return ChildrenInstance

            def FindFirstChild(self, ChildName):
                return toInstance(FindFirstChildW(self.Address, ChildName))

            def FindFirstClass(self, ChildClass):
                return toInstance(FindFirstChildOfClass(self.Address, ChildClass))

            def SetParent(self, Parent):
                setParent(self.Address, Parent)

            def __getattr__(self, ChildName):
                return toInstance(FindFirstChildW(self.Address, ChildName))

        ClearDetection()
        game = toInstance(GetDataModel())
        if game:
            print("Game found\n")
            CoreGui = game.CoreGui
            if CoreGui:
                print("CoreGui found\n")
                rg = CoreGui.RobloxGui
                if rg:
                    print("RobloxGui found\n")
            root = tk.Tk()
            explorer = ExplorerUI(root)
            explorer.populate(game)
            root.mainloop()

        return True
    except Exception as e:
        print(e)
        messagebox.showinfo("Explorer", f"Something went wrong! Please try again.")
        return False


inject()
