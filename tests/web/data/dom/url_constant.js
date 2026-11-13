// Trap: a URL object built from a constant is not the page URL.
const api = new URL("https://api.example.test/v1/items?limit=10");
document.getElementById("out").innerHTML = api.searchParams.get("limit");
