from django.shortcuts import render, redirect, get_object_or_404
from .models import ThreatIP
from .forms import ThreatIPForm
from authsystem.decorators import role_required

@role_required(['admin', 'analyst', 'viewer'])
def threats_list(request):
    items = ThreatIP.objects.order_by("-created_at")
    return render(request, "threatintel/threats_list.html", {"items": items})

@role_required(['admin'])
def threats_add(request):
    if request.method == "POST":
        form = ThreatIPForm(request.POST)
        if form.is_valid():
            form.save()
            return redirect("threatintel:list")
    else:
        form = ThreatIPForm()
    return render(request, "threatintel/threats_add.html", {"form": form})

@role_required(['admin'])
def threats_delete(request, pk):
    t = get_object_or_404(ThreatIP, pk=pk)
    t.delete()
    return redirect("threatintel:list")
