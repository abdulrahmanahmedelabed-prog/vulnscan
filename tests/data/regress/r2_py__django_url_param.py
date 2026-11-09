from django.http import FileResponse

def template_view(request, prompt):
    return FileResponse(open("/srv/prompts/" + prompt + ".txt", "rb"))
