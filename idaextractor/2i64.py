import idc
import ida_auto
import ida_pro
# logging.basicConfig(filename=log_file_name, level=logging.DEBUG)
# logging.debug("Before autoWait")
# autoWait()

# logging.debug("After autoWait")

def export_i64():
    # idc.Wait()
    # idc.save_database("./aa")
    pass
if __name__ == "__main__":
    export_i64()
    ida_auto.auto_wait()
    ida_pro.qexit(0)

