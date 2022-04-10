import org.apache.commons.codec.binary.Hex;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.Security;
import java.sql.*;
import java.util.*;

//...............................................................
public class RaspberryJavaServer {
    static int PORT;

    public static void main(String[] args) throws IOException {
        FileInputStream fis = new FileInputStream("src/config.properties");
        Properties prop = new Properties();
        prop.load(fis);
        Encryption.setKey(prop.getProperty("key"));
        PORT = Integer.parseInt(prop.getProperty("PORT"));
        PostgreSQL postgreSQL = new PostgreSQL(prop.getProperty("connectionString"));
        ServerSocket s = new ServerSocket(PORT);
        System.out.println("Server Started");
        Clients clt = new Clients();
        SmartDevices devices = new SmartDevices(clt);
        new CentralCommand(devices);
        try {
            while (true) {
                Socket socket = s.accept();     // Blocks until a connection occurs:
                socket.setSoTimeout(10 * 1000); // Sets a timeout - if the time elapses without any data arriving the socket is closed
                try {
                    new ServeOneClient(socket, clt, devices);
                    System.out.println("join a new client - total number " + clt.nCl());
                } catch (IOException e) {
                    // If it fails, close the socket,
                    // otherwise the thread will close it:
                    socket.close();
                    System.out.println("catch out");
                    System.out.println(Thread.currentThread().getName());
                }
            }
        } finally {
            s.close();
            CentralCommand.terminate();
            PostgreSQL.terminate();
        }
    }
}

//...............................................................
class Clients {
    private final ArrayList<PrintWriter> pW;

    public Clients() {
        pW = new ArrayList<>(10);
    }

    public synchronized void addC(PrintWriter p) {
        pW.add(p);
    }

    public synchronized void rmvC(PrintWriter p) {
        pW.remove(p);
    }

    public synchronized void sendC(String s) {
        for (PrintWriter p : pW) {
            p.println(s);
        }
    }

    public synchronized int nCl() {
        return pW.size();
    }

}

//...............................................................
class Encryption {

    private static String key = "xxxxxxxxxxxxxxxx";

    public static void setKey(String k) {
        key = k;
    }

    static {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
    }

    public static String encrypt(String input) {
        byte[] crypted = null;
        try {

            SecretKeySpec skey = new SecretKeySpec(key.getBytes(), "AES");

            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS7Padding");//PKCS7Padding
            cipher.init(Cipher.ENCRYPT_MODE, skey);
            crypted = cipher.doFinal(input.getBytes());
        } catch (Exception e) {
            e.printStackTrace();
        }

        return new String(Hex.encodeHex(crypted));   //.toUpperCase();
    }

    public static String decrypt(String input) {
        byte[] output = null;
        try {
            SecretKeySpec skey = new SecretKeySpec(key.getBytes(), "AES");
            Cipher cipher = Cipher.getInstance("AES/ECB/NOPadding");//PKCS7Padding
            cipher.init(Cipher.DECRYPT_MODE, skey);
//            output = cipher.doFinal(Base64.decodeBase64(input));
            output = cipher.doFinal(Hex.decodeHex(input.toCharArray()));
        } catch (Exception e) {
            e.printStackTrace();
        }
        String back = null;
        if (output != null) {
            String outputSTR = new String(output);
            int flag = 0;
            for (int i = 0; i < outputSTR.length(); i++) {
                if (outputSTR.charAt(i) == '{') flag++;
                if (outputSTR.charAt(i) == '}') flag--;
                if (flag == 0) {
                    back = outputSTR.substring(0, i + 1);
                    break;
                }
            }
        }
        return back;
    }
}

//...............................................................
//ако няколко андроида поискат данни едновременно да има някаква синхронизация
class PostgreSQL extends Thread {
    private static volatile boolean loop = true;
    static Statement statement;
    static String connectionString;

    PostgreSQL(String con) {
        connectionString = con;
        start();
    }

    public static void test() {
        try (Connection connection = DriverManager.getConnection(connectionString)) {
            if (connection != null) {
                System.out.println("Connected to PostgreSQL server successfully!");
                statement = connection.createStatement();
            } else {
                System.out.println("Failed to connect to PostgreSQL server...");
            }
            System.out.println("mid update get data");
            ResultSet resultSet = statement.executeQuery("SELECT * FROM \"testTable\";");
            while (resultSet.next()) {
                String name = resultSet.getString("name");
                System.out.println(name);
            }
        } catch (SQLException throwables) {
            throwables.printStackTrace();
            System.out.println("Error connecting to PostgreSQL server");
        }
    }

    public void run() {
        try (Connection connection = DriverManager.getConnection(connectionString)) {
            if (connection != null) {
                System.out.println("Connected to PostgreSQL server successfully!");
                statement = connection.createStatement();
            } else {
                System.out.println("Failed to connect to PostgreSQL server...");
            }

            while (loop) {
                System.out.println("DB update!");

                try {
                    ResultSet resultSet = statement.executeQuery("SELECT * FROM \"testTable\";");
                    while (resultSet.next()) {
                        String name = resultSet.getString("name");
                        System.out.println(name);
                    }
                } catch (SQLException e) {
                    e.printStackTrace();
                }


                try {
                    Thread.sleep(60000);
                } catch (InterruptedException e) {
                    e.printStackTrace();
                }
            }
        } catch (SQLException throwables) {
            throwables.printStackTrace();
            System.out.println("Error connecting to PostgreSQL server");
        }
    }

    public static void terminate() {
        loop = false;
    }
}

//...............................................................
class ServeOneClient extends Thread {
    private final Socket socket;
    private final BufferedReader in;
    private final PrintWriter out;
    Clients clt;
    SmartDevices devices;
    JSONParser parser;
    private volatile boolean loop = true;

    int ID = 0;

    public ServeOneClient(Socket s, Clients clt, SmartDevices devices) throws IOException {
        socket = s;
        this.clt = clt;
        this.devices = devices;
        in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
        out = new PrintWriter(new BufferedWriter(new OutputStreamWriter(socket.getOutputStream())), true);
        clt.addC(out);
        parser = new JSONParser();

        start();
    }


    public void run() {
        try {
            while (loop) {
                Map data = readAll();

                System.out.println();
                System.out.println("Sender: " + ID);

                /*if (ID >= 500) {        // should be <= or what? !!!!!!
                    //controller input // андроида ще праща стринг с инструкция във 1 променлива във мапа
                    if (data != null) {
                        String command = (String) data.get("command");
                        System.out.println(command);
                        if (command != null) {
                            handleCommand(command);
                        }
                    }
                } else if (ID > 0) {
                    //sensors
                    for (Map.Entry pair : (Iterable<Map.Entry>) data.entrySet()) {
                        Storage.mapStorage.put(pair.getKey(), pair.getValue());
                        System.out.println(pair.getKey() + " : " + pair.getValue());
                    }

                }*/

                switch (ID){
                    case 1:     //bathroom Fan
                        dataToStorage(data);
                        //devices.bathroomFan.respond();    //idea if the command is broadcast and not personal
                        break;
                    default:    //controller input // андроида ще праща стринг с инструкция във 1 променлива във мапа
                        if (data != null) {
                            String command = (String) data.get("command");
                            System.out.println(command);
                            if (command != null) {
                                handleCommand(command);
                            }
                        }
                }

                System.out.println("total number of sockets: " + clt.nCl());
                //System.out.println(data);
            }
        } catch (IOException e) {
            loop = false;
        } finally {
            try {
                loop = false;
                clt.rmvC(out);
                System.out.println("disconnect a client. Total number " + clt.nCl());
                socket.close();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }

    Map readAll() throws IOException {
        Map data = null;

        String str = in.readLine();
        //if (str.equals("END")) loop = false;

        if (str != null && str.length() > 5) {
            String decrypted = Encryption.decrypt(str);
            if (decrypted != null) {
                char[] charArr = decrypted.toCharArray();   //get the first char to see if it is json
                if (charArr[0] == '{') {
                    JSONObject json = null; //ако е някакъв произволен пакет или има грешка - json parsera се шашка и бие грешка
                    try {
                        json = (JSONObject) parser.parse(decrypted);
                    } catch (ParseException e) {
                        e.printStackTrace();
                    }
                    if (json != null) {
                        /////////////do stuff here
                        long x = (long) json.get("ID");
                        ID = (int) x;
                        /////////////
                        data = ((Map) json.get("data"));
                        /////////////
                    } else {
                        System.out.println("json not parsed correctly");
                        loop = false;
                    }
                } else {
                    System.out.println("no correct json decrypted");
                    loop = false;
                }
            } else {
                System.out.println("decrypted string is null");
                loop = false;
            }
        } else {
            System.out.println("empty string received");
            loop = false;
        }
        return data;
    }

    void dataToStorage(Map data){
        for (Map.Entry pair : (Iterable<Map.Entry>) data.entrySet()) {
            Storage.mapStorage.put(pair.getKey(), pair.getValue());
            System.out.println(pair.getKey() + " : " + pair.getValue());
        }
    }

    void handleCommand(String command) {
        switch (command) {
            case "giveData":
                JSONObject jo = new JSONObject();
                jo.put("ID", 999);
                jo.put("data", Storage.mapStorage);
                String data = jo.toString();
                String encrypted = Encryption.encrypt(data);
                out.println(encrypted);              //only to the client of this thread
                System.out.println("here is your data");
                System.out.println(Storage.mapStorage);
                break;
            case "bathroomFanON":
                Storage.bathroomFanMode = Storage.Mode.ON;
                Storage.mapStorage.put("bathroomFanMode", "on");
                devices.bathroomFan.switchON();
                break;
            case "bathroomFanAuto":
                Storage.bathroomFanMode = Storage.Mode.AUTO;
                Storage.mapStorage.put("bathroomFanMode", "auto");
                break;
            case "bathroomFanOFF":
                Storage.bathroomFanMode = Storage.Mode.OFF;
                Storage.mapStorage.put("bathroomFanMode", "off");
                devices.bathroomFan.switchOFF();
                break;
            case "dataDB":
                System.out.println("data from db");
                PostgreSQL.test();
                //handle data and send back to android
        }
    }
}

//...............................................................
class Storage {
    enum Mode {ON, OFF, AUTO}

    static Map mapStorage = new LinkedHashMap();
    static Mode bathroomFanMode = Mode.AUTO;
    //"bathroomFanMode", "auto"
    //"BathroomFanDelay", 30
}

//...............................................................
class CentralCommand extends Thread {
    private static volatile boolean loop = true;
    int repeatInterval = 10; //delay between loops in ms //at 100 arduino cant decrypt in time xD
    // might have to implement restrictions on broadcasts per sec (if 2 arduinos have to get commands at once)
    SmartDevices devices;

    //calls the Control method of all devices and executes it at a certain intervals
    CentralCommand(SmartDevices devices) {
        this.devices = devices;
        start();
    }

    //automation thread
    public void run() {
        while (loop) {

            if (Storage.bathroomFanMode == Storage.Mode.AUTO) {
                devices.bathroomFan.Auto(repeatInterval);
            }


            try {
                Thread.sleep(repeatInterval);
            } catch (InterruptedException e) {
                e.printStackTrace();
            }
        }
    }

    public static void terminate() {
        loop = false;
    }
}

//...............................................................
class SmartDevices {
    Clients clt;

    BathroomFan bathroomFan;

    SmartDevices(Clients clt) {
        this.clt = clt;

        bathroomFan = new BathroomFan(clt);

    }
}

//...............................................................
//must test case: manual command given but auto changes state at the last ms
class BathroomFan {
    Clients clt;

    JSONObject jo;
    int counterForBathroomFan = 0;
    int noResponse = 0;
    int counterSpamDelay = 0;
    boolean flag = false;

    static int fanCom = 0;

    BathroomFan(Clients clt) {
        this.clt = clt;
    }

    public synchronized void Auto(int repeatInterval) {
        Storage.mapStorage.put("bathroomFanMode", "auto");
        Storage.mapStorage.put("bathroomFanDelay", 1);
        Double bathTemp = null;
        Double bathHum = null;
        Double bathLight = null;
        boolean bathFan = false;

        double BathroomFanDelay = Double.parseDouble(Storage.mapStorage.get("bathroomFanDelay").toString()) / ((double) repeatInterval / 1000);
        double spamDelay = 2 / ((double) repeatInterval / 1000);

        if (Storage.mapStorage.get("bathTemp") != null) {
            bathTemp = Double.valueOf(Storage.mapStorage.get("bathTemp").toString());
        }
        if (Storage.mapStorage.get("bathHum") != null) {
            bathHum = Double.valueOf(Storage.mapStorage.get("bathHum").toString());
        }
        if (Storage.mapStorage.get("bathLight") != null) {
            bathLight = Double.valueOf(Storage.mapStorage.get("bathLight").toString());
        }
        if (Storage.mapStorage.get("bathFan") != null) {
            bathFan = (boolean) Storage.mapStorage.get("bathFan");
        }

        if (bathHum != null && bathLight != null && bathTemp != null) {
            if ((bathHum > 60 || bathLight >= 0.01) && !bathFan) {
                //fanCom = 1;
                if (counterSpamDelay == 0) {
                    switchON();
                    counterSpamDelay = (int)spamDelay;
                }
                counterForBathroomFan = 0;
            } else if (bathHum < 50 && bathLight < 0.01 && bathFan) {
                if (counterForBathroomFan >= BathroomFanDelay) {
                    //fanCom = 2;
                    if (counterSpamDelay == 0) {
                        switchOFF();
                        counterSpamDelay = (int)spamDelay;
                    }
                } else {
                    counterForBathroomFan++;
                    //System.out.println("off delay: " + counterForBathroomFan);
                }
            } else {
                //fanCom = 0;
                if (bathLight >= 0.01) counterForBathroomFan = 0;
            }
            if (counterSpamDelay > 0) {
                counterSpamDelay--;
                //System.out.println("spam: " + counterSpamDelay);
            }

        } else {
            System.out.println("no data from bathroomFan");
        }
    }

    public synchronized void switchON() {
        System.out.println("switch it on");
        jo = new JSONObject();
        jo.put("ID", 1);
        jo.put("data", true);
        String data = jo.toString();
        System.out.println(data);
        String encrypted = Encryption.encrypt(data);
        clt.sendC(encrypted);
    }

    public synchronized void switchOFF() {
        System.out.println("switch it off");
        jo = new JSONObject();
        jo.put("ID", 1);
        jo.put("data", false);
        String data = jo.toString();
        String encrypted = Encryption.encrypt(data);
        clt.sendC(encrypted);
    }
/*
    public synchronized void respond(){

    }
 */
}
//...............................................................
//todo
/*
индикация че дадено устройство се е откачило

да преместя обработката на команда от андроида в класа на съответното устройство

да синхронизирам мап променливата за да не пишат и четат едновременно от нея !!!
това може да го проуча от примерите на даскала

адекватен начин за парсването на ID long
*/