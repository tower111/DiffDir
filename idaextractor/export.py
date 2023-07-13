
import idaapi
import ida_auto
import ida_nalt
ida_auto.auto_wait()

filename=ida_nalt.get_input_file_path()
idaapi.ida_expr.eval_idc_expr(None, ida_idaapi.BADADDR,
  'BinExportBinary("{}.BinExport");'.format(filename))

ida_pro.qexit(0)