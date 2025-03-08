from rich.panel import Panel

from . import console


def print_banner() -> None:
    """Display a fancy banner for the application"""
    console.print(Panel.fit(
        "[bold blue]SIMPLE FILE CRYPTER[/bold blue]\n"
        "[dim]Version 2.0[/dim]",
        border_style="yellow",
        padding=(1, 10),
        title="[bold green]🔒[/bold green]",
        subtitle="[bold red]🔑[/bold red]"
    ), justify="center")
    console.print(
        "[italic]A secure file encryption tool[/italic]\n©Muddyblack 2025\n\n",
        justify="center"
    )
