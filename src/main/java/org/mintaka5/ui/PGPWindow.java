package org.mintaka5.ui;

import com.formdev.flatlaf.FlatDarkLaf;
import com.formdev.flatlaf.FlatLightLaf;
import org.bouncycastle.bcpg.ArmoredInputStream;
import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.*;
import org.mintaka5.crypto.ThingPGP;
import org.mintaka5.util.Utilities;

import javax.swing.*;
import javax.swing.border.Border;
import javax.swing.border.EmptyBorder;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import javax.swing.event.ListSelectionEvent;
import javax.swing.event.ListSelectionListener;
import java.awt.*;
import java.awt.event.KeyEvent;
import java.awt.event.KeyListener;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.Security;
import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.stream.Stream;

import static java.lang.System.out;

public class PGPWindow extends JFrame {
    public final static String PUBLIC_KEY_PREFIX = "public-";
    public final static Border DEFAULT_BORDER = BorderFactory.createEmptyBorder(3, 3, 3, 3);

    public final static String SECRET_KEY_PREFIX = "sercret-";
    private static final String DATE_FORMAT_DEFAULT = "YYYY-MM-dd HH:mm:ss";
    private static final String ENC_MSG_PREFIX = "red-";

    private JButton genBtn;

    private JPasswordField passwdTxt;

    private JTextField identTxt;

    private Path keysPath;
    private Path msgsPath;

    private JList<String> chainList;

    private String[] filenames;

    private JTextField userIdentLbl;
    private PGPPublicKey currentEncryptionKey = null;
    private JPasswordField passwdPrompt;
    private PGPPrivateKey currentDecryptionKey = null;
    private JDialog passwdFrame;
    private JTextField keyCreatedLbl;
    private JTextArea msgTxt;
    private JButton encBtn;
    private String hashId;
    private JTextArea decryptTxt;
    private JButton decBtn;
    private JTextField idLbl;
    private JList<String> msgList;
    private String[] msgFiles;
    private String currentMsgId;

    public PGPWindow() throws IOException, PGPException {
        super("pgp thing");

        // setup window
        setupWindow();

        // set up instance below
        // create storage paths
        createPaths();

        // add ui stuff below this line
        // key generation panel
        buildkeyGenPanel();
        // key details panel
        buildKeyInfoPanel();
        // keychain list panel
        buildKeychainPanel();
        // message panel
        buildMessagePanel();
        // messages list
        buildMessageListPanel();

        // show window!
        setVisible(true);
    }

    private void buildMessageListPanel() throws IOException {
        JPanel pnl = new JPanel();
        GridBagLayout gb = new GridBagLayout();
        GridBagConstraints gc = new GridBagConstraints();
        pnl.setLayout(gb);

        gc.insets = new Insets(5, 5, 5, 5);
        gc.gridx = 0;
        gc.gridy = 0;
        gc.weighty = 0;
        gc.fill = GridBagConstraints.HORIZONTAL;
        JLabel msgListLbl = new JLabel("my messages");
        pnl.add(msgListLbl, gc);

        gc.gridy = 1;
        gc.weighty = 1;
        gc.fill = GridBagConstraints.BOTH;
        msgList = new JList<String>();
        msgList.setEnabled(false);
        msgList.addListSelectionListener(new ListSelectionListener() {
            @Override
            public void valueChanged(ListSelectionEvent e) {
                if(e.getValueIsAdjusting()) {
                    try {
                        processMessageSelect();
                    } catch (IOException ex) {
                        throw new RuntimeException("unable to process selected message. ".concat(ex.getMessage()));
                    }
                }
            }
        });
        JScrollPane scroll = new JScrollPane(msgList);
        updateMessageList();
        pnl.add(scroll, gc);

        add(pnl, BorderLayout.EAST);
    }

    private void processMessageSelect() throws IOException {
        // clear all previous things
        msgTxt.setText("");
        msgTxt.setEnabled(false);
        encBtn.setEnabled(false);

        currentMsgId = msgList.getSelectedValue().substring(0, msgList.getSelectedValue().indexOf(" @")).strip();
        Path fileP = Files.list(msgsPath).filter((f) -> f.toString().contains(currentMsgId)).findFirst().get();
        ArmoredInputStream ais = new ArmoredInputStream(new BufferedInputStream(new FileInputStream(fileP.toFile())));
        byte[] encMsg = ais.readAllBytes();
        String encMsgS = new String(encMsg, StandardCharsets.UTF_8);
        decryptTxt.setText(encMsgS);
    }

    private void postPassword() {
        {
            char[] passC = passwdPrompt.getPassword();

            if(passC.length > 0) {
                try {
                    Path pubP = Files.list(keysPath).filter((f) -> f.getFileName().toString().contains(hashId) && f.getFileName().toString().contains(PUBLIC_KEY_PREFIX)).findFirst().get();
                    PGPPublicKeyRing pubRing = ThingPGP.importPublicKeyring(pubP.toFile());
                    currentEncryptionKey = ThingPGP.getEncryptionKey(pubRing);

                    Path secP = Files.list(keysPath).filter((f) -> f.getFileName().toString().contains(hashId) && f.getFileName().toString().contains(SECRET_KEY_PREFIX)).findFirst().get();
                    PGPSecretKeyRing secRing = ThingPGP.importSecretKeyring(secP.toFile());
                    currentDecryptionKey = ThingPGP.getDecryptionKey(secRing, currentEncryptionKey.getKeyID(), String.copyValueOf(passC));

                    userIdentLbl.setText(pubRing.getPublicKey().getUserIDs().next());
                    Instant keyInstant = currentEncryptionKey.getCreationTime().toInstant();
                    String keyCreated = DateTimeFormatter.ofPattern(DATE_FORMAT_DEFAULT).withZone(ZoneId.systemDefault()).format(keyInstant);
                    keyCreatedLbl.setText(keyCreated);

                    idLbl.setText(hashId);

                    passwdFrame.setVisible(false);
                    chainList.clearSelection();

                    // activate message panel items
                    msgTxt.setEnabled(true);

                    // activate message list as well since we have a current key set
                    msgList.setEnabled(true);
                } catch (IOException | PGPException ex) {

                    // the password was incorrect or something went wrong when trying to expose secret key
                    // throw new RuntimeException("unable to find files containing specified hash identifier.".concat(ex.getMessage()));
                }
            }
        }
    }

    private void updateMessageList() throws IOException {
        msgFiles = Files.list(msgsPath).map((f) -> {
            Instant created = Instant.ofEpochMilli(f.toFile().lastModified());
            String createdS = DateTimeFormatter.ofPattern(DATE_FORMAT_DEFAULT).withZone(ZoneId.systemDefault()).format(created);
            String fname = f.getFileName().toString();
            fname = fname.replace(ENC_MSG_PREFIX, "")
                    .replace(".asc", "");
            // fname = fname.substring(0, fname.indexOf("-"));

            return fname.concat(" @ ").concat(createdS);
        }).toArray(String[]::new);

        msgList.setListData(msgFiles);
    }

    private void setupWindow() {
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        setLocationByPlatform(true);
        setLayout(new BorderLayout());
        // setSize(640, 480);
        setMinimumSize(new Dimension(960, 720));
        setSize(960, 720);
        // setSize(1024, 768);
        // setResizable(false);

        FlatLightLaf.setup();
        FlatDarkLaf.setup();

        SwingUtilities.invokeLater(() -> {
            try {
                UIManager.setLookAndFeel(new FlatDarkLaf());
            } catch (UnsupportedLookAndFeelException e) {
                throw new RuntimeException(e);
            }
        });
    }

    private void createPaths() throws IOException {
        keysPath = Path.of(System.getProperty("user.home"), ".archivr", "keys");
        msgsPath = Path.of(System.getProperty("user.home"), ".archivr", "msgs");

        // operations
        // set up directory for storage
        if(!Files.exists(keysPath)) {
            Files.createDirectories(keysPath);
        }

        if(!Files.exists(msgsPath)) {
            Files.createDirectories(msgsPath);
        }
    }

    private void buildKeyInfoPanel() {
        JPanel panel = new JPanel();
        panel.setBorder(DEFAULT_BORDER);
        panel.setBorder(new EmptyBorder(5, 5, 5, 5));
        GridBagLayout gbl = new GridBagLayout();
        GridBagConstraints gbc = new GridBagConstraints();
        panel.setLayout(gbl);

        gbc.insets = new Insets(5, 5, 5, 5);

        // 0, 0
        gbc.gridx = 0;
        gbc.gridy = 0;
        panel.add(new JLabel("id"));

        // 1, 0
        gbc.gridx = 1;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.weightx = 1;
        idLbl = new JTextField();
        idLbl.setEnabled(false);
        panel.add(idLbl, gbc);

        // 2, 0
        gbc.gridx = 2;
        panel.add(new JLabel("identifier"));

        // 3, 0
        gbc.gridx = 3;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.weightx = 1;
        userIdentLbl = new JTextField();
        userIdentLbl.setEnabled(false);
        panel.add(userIdentLbl, gbc);

        // 0, 1
        gbc.gridx = 0;
        gbc.gridy = 1;
        gbc.weightx = 0;
        panel.add(new JLabel("created"), gbc);

        // 1, 1
        gbc.gridx = 1;
        gbc.gridy = 1;
        gbc.weightx = 1;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        keyCreatedLbl = new JTextField();
        keyCreatedLbl.setEnabled(false);
        panel.add(keyCreatedLbl, gbc);

        add(panel, BorderLayout.SOUTH);
    }

    private void buildMessagePanel() {
        JPanel panel = new JPanel();
        panel.setBorder(DEFAULT_BORDER);
        GridBagLayout gb = new GridBagLayout();
        GridBagConstraints gc = new GridBagConstraints();
        panel.setLayout(gb);

        gc.insets = new Insets(5, 5, 5, 5);

        gc.weightx = 1;
        gc.gridx = 0;
        gc.gridy = 0;
        gc.fill = GridBagConstraints.HORIZONTAL;
        gc.weighty = 0;
        JLabel msgLbl = new JLabel("message");
        panel.add(msgLbl, gc);

        gc.fill = GridBagConstraints.BOTH;
        gc.gridx = 0;
        gc.gridy = 1;
        gc.weighty = 1;
        msgTxt = new JTextArea();
        JScrollPane msgScroll = new JScrollPane(msgTxt);
        msgTxt.setWrapStyleWord(true);
        msgTxt.setLineWrap(true);
        msgTxt.setEnabled(false);
        msgTxt.addKeyListener(new KeyListener() {
            @Override
            public void keyTyped(KeyEvent e) {}

            @Override
            public void keyPressed(KeyEvent e) {}

            @Override
            public void keyReleased(KeyEvent e) {
                encBtn.setEnabled((msgTxt.getText().length() > 0));
            }
        });
        msgTxt.getDocument().addDocumentListener(new DocumentListener() {
            @Override
            public void insertUpdate(DocumentEvent e) {
                if(msgTxt.getText().length() > 0) {
                    msgTxt.setEnabled(true);
                    encBtn.setEnabled(true);
                }
            }

            @Override
            public void removeUpdate(DocumentEvent e) {
                msgTxt.setEnabled(false);
                encBtn.setEnabled(false);
            }

            @Override
            public void changedUpdate(DocumentEvent e) {

            }
        });
        panel.add(msgScroll, gc);

        gc.fill = GridBagConstraints.HORIZONTAL;
        gc.gridy = 2;
        gc.weighty = 0;
        encBtn = new JButton("encrypt");
        encBtn.setEnabled(false);
        encBtn.addActionListener((e) -> {
            msgTxt.setEnabled(false);
            encBtn.setEnabled(false);

            byte[] msgB = msgTxt.getText().getBytes(StandardCharsets.UTF_8);
            try {
                // write to messages folder
                byte[] encB = ThingPGP.encrypt(currentEncryptionKey, msgB);
                // save to file
                Path msgP = Path.of(msgsPath.toString(), ENC_MSG_PREFIX.concat(hashId).concat(".asc"));
                // need another unique string to create a unique filename
                String fname = msgP.toString();
                String fileH = Utilities.crc32(hashId.concat(";").concat(fname).concat(String.valueOf(Instant.now().toEpochMilli())));
                msgP = Path.of(msgsPath.toString(), ENC_MSG_PREFIX.concat(hashId).concat("-").concat(fileH).concat(".asc"));

                ArmoredOutputStream aos = new ArmoredOutputStream(new BufferedOutputStream(new FileOutputStream(msgP.toFile())));
                aos.write(encB);
                aos.flush();
                aos.close();
                msgTxt.setText("");

                decryptTxt.setText(Files.readString(msgP));

                chainList.clearSelection();

                updateMessageList();

            } catch (IOException | PGPException ex) {
                throw new RuntimeException(ex);
            }
        });
        panel.add(encBtn, gc);

        gc.gridy = 3;
        JLabel decLbl = new JLabel("secret message");
        panel.add(decLbl, gc);

        gc.fill = GridBagConstraints.BOTH;
        gc.gridy = 4;
        gc.weighty = 1;
        decryptTxt = new JTextArea();
        JScrollPane decScroll = new JScrollPane(decryptTxt);
        decryptTxt.setWrapStyleWord(true);
        decryptTxt.setLineWrap(true);
        decryptTxt.setEnabled(false);
        decryptTxt.getDocument().addDocumentListener(new DocumentListener() {
            @Override
            public void insertUpdate(DocumentEvent e) {
                decBtn.setEnabled((currentDecryptionKey != null));
            }

            @Override
            public void removeUpdate(DocumentEvent e) {
                decBtn.setEnabled(false);
            }

            @Override
            public void changedUpdate(DocumentEvent e) {}
        });
        panel.add(decScroll, gc);

        gc.fill = GridBagConstraints.HORIZONTAL;
        gc.gridy = 5;
        gc.weighty = 0;
        decBtn = new JButton("decrypt");
        decBtn.setEnabled(false);
        decBtn.addActionListener((e) -> {
            if(currentDecryptionKey != null && !currentMsgId.isEmpty()) {
                try {
                    Path msgP = Files.list(msgsPath).filter((f) -> f.getFileName().toString().contains(currentMsgId)).findFirst().get();
                    ArmoredInputStream ais = new ArmoredInputStream(new FileInputStream(msgP.toFile()));
                    byte[] decB = ais.readAllBytes();
                    byte[] clearB = ThingPGP.decrypt(currentDecryptionKey, decB);
                    msgTxt.setText(new String(clearB, StandardCharsets.UTF_8));
                    decryptTxt.setText("");
                } catch (Exception ex) {
                    // reset all current message stuff
                    decryptTxt.setText("");
                    msgList.clearSelection();
                    throw new RuntimeException("failed to decrypt message. check key ID. ".concat(ex.getMessage()));
                }
            }
        });
        panel.add(decBtn, gc);

        add(panel, BorderLayout.CENTER);
    }

    private void buildKeychainPanel() throws IOException {
        JPanel panel = new JPanel();
        panel.setBorder(DEFAULT_BORDER);
        GridBagLayout gb = new GridBagLayout();
        GridBagConstraints gc = new GridBagConstraints();
        panel.setLayout(gb);

        gc.insets = new Insets(5, 5, 5, 5);

        gc.gridx = 0;
        gc.gridy = 0;
        gc.weightx = 1;
        gc.fill = GridBagConstraints.HORIZONTAL;
        JLabel chainLbl = new JLabel("my keys");
        panel.add(chainLbl, gc);

        gc.gridx = 0;
        gc.gridy = 1;
        gc.weighty = 1;
        gc.fill = GridBagConstraints.BOTH;
        chainList = new JList<String>();
        JScrollPane chainPane = new JScrollPane(chainList);
        chainList.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        chainList.addListSelectionListener((e) -> {
            // only select if we are moving to a new item in list
            // and don't show password prompt unless something is selected
            if(!e.getValueIsAdjusting() && !chainList.isSelectionEmpty()) {
                hashId = chainList.getSelectedValue().replaceAll(" @ .*", "");

                // since secret key rings are password protected,
                // user needs to provide password
                showPasswordPrompt(hashId);
            }
        });
        panel.add(chainPane, gc);
        updateChainList();

        add(panel, BorderLayout.WEST);
    }

    private void showPasswordPrompt(String hashId) {
        GridBagLayout gbl = new GridBagLayout();
        GridBagConstraints gbc = new GridBagConstraints();

        JPanel passwdPanel = new JPanel();
        passwdPanel.setBorder(BorderFactory.createEmptyBorder(5, 5, 5, 5));
        passwdPanel.setLayout(gbl);

        gbc.insets = new Insets(5, 5, 5, 5);
        gbc.gridx = 0;
        gbc.gridy = 0;
        gbc.weightx = 1;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        passwdPrompt = new JPasswordField();
        passwdPrompt.addKeyListener(new KeyListener() {
            @Override
            public void keyTyped(KeyEvent e) {}

            @Override
            public void keyPressed(KeyEvent e) {}

            @Override
            public void keyReleased(KeyEvent e) {
                if(e.getKeyCode() == 10) {
                    postPassword();
                }
            }
        });
        passwdPrompt.setColumns(25);
        passwdPanel.add(passwdPrompt, gbc);

        gbc.fill = GridBagConstraints.NONE;
        gbc.gridx = 0;
        gbc.gridy = 1;
        gbc.weightx = 0;
        JButton submitBtn = new JButton("submit");
        passwdPanel.add(submitBtn, gbc);

        passwdFrame = new JDialog(this, "enter password!", true);
        passwdFrame.setResizable(false);
        passwdFrame.setSize(new Dimension(200, 180));
        passwdFrame.setLocationByPlatform(true);
        passwdFrame.getRootPane().setBorder(DEFAULT_BORDER);
        passwdFrame.getContentPane().add(passwdPanel);

        submitBtn.addActionListener(e -> postPassword());

        passwdFrame.setVisible(true);
    }

    private void updateChainList() throws IOException {
        chainList.removeAll();

        filenames = Files.list(keysPath).map(
                (f) -> f.getFileName().toString().replace(".asc", "")
                        .replace(PUBLIC_KEY_PREFIX, "")
                        .replace(SECRET_KEY_PREFIX, "")
                        .concat(" @ ")
                        .concat(
                                DateTimeFormatter.ofPattern(DATE_FORMAT_DEFAULT)
                                        .withZone(ZoneId.systemDefault())
                                        .format(Instant.ofEpochMilli(f.toFile().lastModified())))
        ).distinct().toArray(String[]::new);
        chainList.setListData(filenames);
    }

    private void buildkeyGenPanel() throws PGPException {
        JPanel keyGenPanel = new JPanel();
        keyGenPanel.setBorder(DEFAULT_BORDER);
        GridBagLayout keyGenLayout = new GridBagLayout();
        GridBagConstraints keyGenGBC = new GridBagConstraints();
        keyGenPanel.setLayout(keyGenLayout);

        keyGenGBC.insets = new Insets(5, 5, 5, 5);
        keyGenGBC.fill = GridBagConstraints.BOTH;
        keyGenGBC.gridx = 0;
        keyGenGBC.gridy = 0;
        keyGenPanel.add(new JLabel("identifier"), keyGenGBC);

        keyGenGBC.weightx = 1;
        keyGenGBC.gridx = 1;
        keyGenGBC.gridy = 0;
        identTxt = new JTextField();
        keyGenPanel.add(identTxt, keyGenGBC);

        keyGenGBC.weightx = 0;
        keyGenGBC.gridx = 2;
        keyGenGBC.gridy = 0;
        keyGenPanel.add(new JLabel("password"), keyGenGBC);

        keyGenGBC.weightx = 1;
        keyGenGBC.gridx = 3;
        keyGenGBC.gridy = 0;
        passwdTxt = new JPasswordField();
        keyGenPanel.add(passwdTxt, keyGenGBC);

        keyGenGBC.weightx = 0;
        keyGenGBC.gridx = 4;
        keyGenGBC.gridy = 0;
        genBtn = new JButton("generate");
        genBtn.addActionListener(e -> {
            // disable the panel
            toggleKeyGenPanel(false);

            String idS = identTxt.getText().strip();

            char[] passC = passwdTxt.getPassword();
            String passS = Stream.of(passC).map(String::valueOf).reduce("", String::concat);

            if(!idS.isEmpty() || passC.length > 0) {
                // go fo launch!
                SwingUtilities.invokeLater(new Runnable() {
                    @Override
                    public void run() {
                        try {
                            // store keys in respective files
                            exportAllKeys(idS, passS);
                            // update the keychain list
                            updateChainList();

                            // reactivate panel
                            toggleKeyGenPanel(true);
                        } catch (IOException | PGPException ex) {
                            throw new RuntimeException(ex);
                        }
                    }
                });
            } else {
                JOptionPane.showMessageDialog(new JFrame(), "please provide both identifier and password!", "key generation error", JOptionPane.ERROR_MESSAGE);
            }
        });
        keyGenPanel.add(genBtn, keyGenGBC);

        add(keyGenPanel, BorderLayout.NORTH);
    }

    private void toggleKeyGenPanel(boolean b) {
        identTxt.setEnabled(b);
        passwdTxt.setEnabled(b);
        genBtn.setEnabled(b);
    }

    private void exportAllKeys(String id, String pass) throws IOException, PGPException {
        PGPKeyRingGenerator keyRing = ThingPGP.generateKeyRing(id, pass);
        Path[] keyFiles = createKeyFilePath(id);
        ThingPGP.exportPublicKey(keyRing, keyFiles[0].toFile(), true);
        ThingPGP.exportSecretKey(keyRing, keyFiles[1].toFile(), true);
    }

    private Path[] createKeyFilePath(String id) {
        String timeS = Instant.now().toString();
        String ip = Utilities.getWideIp();
        String temp = ip.concat(";").concat(id).concat(";").concat(timeS);

        String hash = Utilities.crc32(temp);

        Path pubP = Path.of(keysPath.toString(), PGPWindow.PUBLIC_KEY_PREFIX.concat(hash).concat(".asc"));
        Path secP = Path.of(keysPath.toString(), PGPWindow.SECRET_KEY_PREFIX.concat(hash).concat(".asc"));

        return new Path[] {pubP, secP};
    }

    public static void main(String[] args) throws IOException, UnsupportedLookAndFeelException, ClassNotFoundException, InstantiationException, IllegalAccessException, PGPException {
        Security.addProvider(new BouncyCastleProvider());

        new PGPWindow();
    }
}
