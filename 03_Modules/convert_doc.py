import pypandoc

try:
    pypandoc.get_pandoc_path()
except OSError:
    print("Downloading pandoc...")
    pypandoc.download_pandoc()

md_file = r'e:\Project\FPT_Research\docs\QuyTrinh_7_Buoc_ShieldAI.md'
docx_file = r'e:\Project\FPT_Research\docs\QuyTrinh_7_Buoc_ShieldAI.docx'

try:
    pypandoc.convert_file(md_file, 'docx', outputfile=docx_file)
    print("Conversion success!")
except Exception as e:
    print(f"Error during conversion: {e}")
