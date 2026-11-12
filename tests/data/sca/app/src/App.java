package com.example;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.core.lookup.JndiLookup;

public class App {
    String f(String k) { return new JndiLookup().lookup(k); }
}
