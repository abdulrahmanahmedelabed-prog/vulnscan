// Trap: history.pushState only changes the address bar of this origin.
history.pushState(null, "", location.hash.slice(1));
