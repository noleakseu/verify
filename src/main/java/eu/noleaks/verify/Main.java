/*
 * Copyright (c) 2012, Axeos B.V, and contributors
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 only, as
 * published by the Free Software Foundation.
 *
 * This code is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * version 2 for more details (a copy is included in the LICENSE file that
 * accompanied this code).
 *
 * You should have received a copy of the GNU General Public License version
 * 2 along with this work; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
 */
package eu.noleaks.verify;

import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.jar.JarFile;
import java.util.logging.*;

final public class Main {
    private static final Verifier VERIFIER = new Verifier();

    public static void main(String[] args) {
        try {
            String file = parseArgs(args);
            if (file == null) {
                showHelp();
            }
            VERIFIER.verifyJar(new JarFile(file));
            System.out.println("verified.");
            System.exit(0);
        } catch (VerifierException e) {
            System.err.println(e.getMessage());
            System.exit(e.getExitCode());
        } catch (Exception e) {
            e.printStackTrace();
            System.exit(127);
        }
    }

    private static void showHelp() {
        System.out.println("Signed ZIP verifier " + Main.class.getPackage().getImplementationVersion());
        System.out.println("Usage:");
        System.out.println("  java -jar verify.jar <options> <file>");
        System.out.println("Options:");
        System.out.println("  -date <yyyy-MM-dd> - check signature validity at given timestamp");
        System.out.println("  -verbose           - show verification steps");
        System.exit(127);
    }

    private static String parseArgs(String[] args) throws ParseException {
        VERIFIER.setLevel(Level.SEVERE);
        for (int i = 0; i < args.length; i++) {
            String arg = args[i];
            if ("-date".equalsIgnoreCase(arg)) {
                String date = args[++i];
                if (i + 1 < args.length && !args[i + 1].startsWith("-")) {
                    date += " " + args[++i];
                }
                VERIFIER.setVerificationDate(new SimpleDateFormat("yyyy-MM-dd").parse(date));
            } else if ("-verbose".equalsIgnoreCase(arg)) {
                VERIFIER.setLevel(Level.ALL);
            } else if (!arg.startsWith("-")) {
                return arg;
            }
        }
        return null;
    }
}
