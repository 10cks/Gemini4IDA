# 可用代码
import idaapi
import ida_hexrays
import idc
from datetime import datetime

class AddComent(idaapi.action_handler_t):
    def __init__(self):
        idaapi.action_handler_t.__init__(self)

    # activation handler
    def activate(self, ctx):
        vu = idaapi.get_widget_vdui(ctx.widget)
        cfunc = ida_hexrays.decompile(vu.cfunc.entry_ea)

        # Create a treeloc_t for the first statement in the function
        tl = ida_hexrays.treeloc_t()
        tl.ea = cfunc.entry_ea
        tl.itp = ida_hexrays.ITP_SEMI

        # Wrap the string in a citem_cmt_t object
        comment = ida_hexrays.citem_cmt_t("这是一个测试注释")

        # Add the comment
        cfunc.user_cmts[tl] = comment

        cfunc.save_user_cmts()  # 保存用户注释
        vu.refresh_ctext()
        return 1

    # update handler is always enabled
    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS


class Hooks(idaapi.UI_Hooks):
    def finish_populating_widget_popup(self, widget, popup_handle):
        if idaapi.get_widget_type(widget) == idaapi.BWN_PSEUDOCODE:
            idaapi.attach_action_to_popup(widget, popup_handle, 'MyPlugin:Comment', "")


hooks = Hooks()
hooks.hook()

class MyPlugin(idaapi.plugin_t):
    flags = idaapi.PLUGIN_FIX
    comment = "我的插件用来添加注释"
    help = "简单地添加一条注释。"
    wanted_name = "MyPlugin"
    wanted_hotkey = ""

    def init(self):
        print("MyPlugin : Plugin Initialized")
        if ida_hexrays.init_hexrays_plugin():
            action_desc = idaapi.action_desc_t(
                'MyPlugin:Comment',
                '添加示例注释',
                AddComent(),
                'Ctrl+H',
                None,
                -1)
            idaapi.register_action(action_desc)
            idaapi.attach_action_to_menu("Edit/Other/", 'MyPlugin:Comment', idaapi.SETMENU_APP)
            return idaapi.PLUGIN_KEEP
        else:
            print("无法初始化 Hex-Rays 插件。")
            return idaapi.PLUGIN_SKIP

    def run(self, arg):
        pass

    def term(self):
        idaapi.unregister_action('MyPlugin:Comment')
        print("MyPlugin: Plugin has terminated")


def PLUGIN_ENTRY():
    return MyPlugin()