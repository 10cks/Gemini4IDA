# 可用代码
import idaapi
import ida_hexrays
import idc
import idautils
import os
import google.generativeai as genai 
from datetime import datetime

os.environ['http_proxy'] = 'http://127.0.0.1:7890'
os.environ['https_proxy'] = 'http://127.0.0.1:7890'

  # 填入自己的api_key
API_KEY=''
genai.configure(api_key=API_KEY)

def GeminiAnalysis(inputCode):

    #模型参数 
    generation_config = { 
        "temperature": 0.9, 
        "top_p": 1, 
        "top_k": 1, 
        "max_output_tokens": 2048, 
    } 

    # 威胁程度
    safety_settings = [ 
        {
            "category": "HARM_CATEGORY_HARASSMENT", 
            "threshold": "BLOCK_MEDIUM_AND_ABOVE" 
        }, 
        { 
            "category": "HARM_CATEGORY_HATE_SPEECH", 
            "threshold": "BLOCK_MEDIUM_AND_ABOVE" 
        }, 
        { 
            "category": "HARM_CATEGORY_SEXUALLY_EXPLICIT", 
            "threshold": "BLOCK_MEDIUM_AND_ABOVE" 
        }, 
        {
            "category": "HARM_CATEGORY_DANGEROUS_CONTENT",
            "threshold": "BLOCK_ONLY_HIGH"
        },
    ]

    model = genai.GenerativeModel(model_name="gemini-pro", 
                                generation_config=generation_config, 
                                safety_settings=safety_settings)

    identity='''
    Identity: A Study in Binary Security
    Goal: My goal is to help improve the security of software and systems by analyzing and studying binaries to find and resolve security vulnerabilities.
    Specific tasks and responsibilities include:
    Analyzing binaries: I can analyze binaries using a variety of tools and techniques, including disassembly, debugging, and dynamic analysis.
    Identifying security vulnerabilities: When analyzing binaries, I pay special attention to looking for pieces of code that can lead to security vulnerabilities, such as buffer overflows, integer overflows, format string vulnerabilities, etc.
    Identity: A Study in Binary Security
    Goal: My goal is to help improve the security of software and systems by analyzing and studying binaries to find and resolve security vulnerabilities.
    Specific tasks and responsibilities include:
    Analyzing binaries: I can analyze binaries using a variety of tools and techniques, including disassembly, debugging, and dynamic analysis.
    Identifying security vulnerabilities: When analyzing binaries, I pay special attention to looking for pieces of code that can lead to security vulnerabilities, such as buffer overflows, integer overflows, format string vulnerabilities, etc.
    Assessing the severity of the vulnerability: I evaluate the severity of the discovered security vulnerabilities and classify them based on their nature and potential impact.
    Develop exploit methods: I will try to develop exploit methods to prove the existence of a security vulnerability and demonstrate how the vulnerability can be exploited.
    Report security vulnerabilities: I will report the discovered security vulnerabilities to the software or system developers and assist them in fixing the vulnerabilities.
    Participation in security research: I will actively participate in security research and share my research results with other security researchers.
    Provide security advice: I provide security advice to software and system developers to help them improve the security of their software and systems.
    My job is important to software and system security because I can help find and resolve security vulnerabilities that can be exploited by malicious attackers to compromise software and systems. Assessing the severity of the vulnerability: I evaluate the severity of the discovered security vulnerabilities and classify them based on their nature and potential impact.
    Develop exploit methods: I will try to develop exploit methods to prove the existence of a security vulnerability and demonstrate how the vulnerability can be exploited.
    Report security vulnerabilities: I will report the discovered security vulnerabilities to the software or system developers and assist them in fixing the vulnerabilities.
    Participation in security research: I will actively participate in security research and share my research results with other security researchers.
    Provide security advice: I provide security advice to software and system developers to help them improve the security of their software and systems.
    My job is important to software and system security because I can help find and resolve security vulnerabilities that can be exploited by malicious attackers to compromise software and systems.
    '''

    code=inputCode

    #输入提示
    prompt_parts = ["Forget the previous question and go back to the analysis.\n"+ 
                    "Your identity is: \n" + 
                    identity + "\n" + 
                    "Don't use markdown syntax to answer questions. Do two things with the following code: 1. Analyze the code flow. 2.The flow of the code is there a vulnerability? If there are vulnerabilities, where are the possible places. \n"+
                    "Please reply in Chinese:\n" +
                    code]

    #输出回答
    response = model.generate_content(prompt_parts) 
    response_str = str(response.text)
    # print(response.text)
    return response_str

class AddComent(idaapi.action_handler_t):
    def __init__(self):
        idaapi.action_handler_t.__init__(self)

    def activate(self, ctx):
        vu = idaapi.get_widget_vdui(ctx.widget)
        cfunc = ida_hexrays.decompile(vu.cfunc.entry_ea)
        entry_ea = cfunc.entry_ea
        tl = ida_hexrays.treeloc_t()
        tl.ea = entry_ea 

        # 获取伪代码
        pseudocode_text = str(cfunc)

        # 收集所有汇编指令
        assembly_instructions = []
        func_items = list(idautils.FuncItems(entry_ea))  # 获取函数中所有指令的地址

        func_name = idc.get_func_name(entry_ea)
        assembly_instructions.append(f"{func_name} proc near")

        for ea in func_items:
            disasm_line = idc.generate_disasm_line(ea, 0)
            if disasm_line:
                assembly_instructions.append("    " + disasm_line)

        assembly_instructions.append(f"{func_name} endp")

        # 将汇编指令列表转换为字符串
        assembly_text = '\n'.join(assembly_instructions)

        # 注释包含伪代码及汇编代码
        # comment_text = f"Pseudo Code:\n{pseudocode_text}\n\nAssembly:\n{assembly_text}"

        # 注释仅包含伪代码
        comment_text = f"Pseudo Code:\n{pseudocode_text}"
        comment = ida_hexrays.citem_cmt_t(GeminiAnalysis(comment_text))
        cfunc.user_cmts[tl] = comment
        cfunc.save_user_cmts()  
        vu.refresh_ctext()
        return 1  

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS

class Hooks(idaapi.UI_Hooks):
    def finish_populating_widget_popup(self, widget, popup_handle):
        if idaapi.get_widget_type(widget) == idaapi.BWN_PSEUDOCODE:
            idaapi.attach_action_to_popup(widget, popup_handle, 'Gemini4IDA:Comment', "")

hooks = Hooks()
hooks.hook()

class MyPlugin(idaapi.plugin_t):

    flags = idaapi.PLUGIN_FIX
    comment = "Gemini4IDA comment"
    help = "Gemini4IDA help"
    wanted_name = "Gemini4IDA"
    wanted_hotkey = ""

    def init(self):
        print("Gemini4IDA v1.0 by 10cks/bwner, 2023")
        print("Gemini4IDA's shortcut key is Ctrl-Shift-H")
        if ida_hexrays.init_hexrays_plugin():
            action_desc = idaapi.action_desc_t(
                'Gemini4IDA:Comment', 
                'Gemini4IDA Analysis',
                AddComent(),
                'Ctrl+Shift+G', 
                None,
                -1)
            idaapi.register_action(action_desc)
            idaapi.attach_action_to_menu("Edit/Other/", 'Gemini4IDA:Comment', idaapi.SETMENU_APP)
            return idaapi.PLUGIN_KEEP
        else:
            print("Unable to initialize Hex-Rays plugin.")
            return idaapi.PLUGIN_SKIP

    def run(self, arg):
        AddComent()
        pass

    def term(self):
        idaapi.unregister_action('Gemini4IDA:Comment')
        print("Gemini4IDA: Plugin has terminated")


def PLUGIN_ENTRY():
    return MyPlugin()
