package org.mintaka5.ui;

import com.google.inject.internal.util.Lists;
import org.apache.commons.collections4.IteratorUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.util.encoders.Hex;
import org.dizitart.no2.FindOptions;
import org.dizitart.no2.Nitrite;
import org.dizitart.no2.SortOrder;
import org.dizitart.no2.WriteResult;
import org.dizitart.no2.event.ChangeInfo;
import org.dizitart.no2.event.ChangeListener;
import org.dizitart.no2.objects.Cursor;
import org.dizitart.no2.objects.ObjectRepository;
import org.dizitart.no2.objects.filters.ObjectFilters;
import org.json.JSONObject;
import org.mintaka5.crypto.ThingPGP;
import org.mintaka5.model.KeyRepo;
import org.mintaka5.ui.component.PubKeyListRenderer;
import org.mintaka5.util.Utilities;

import javax.swing.*;
import javax.swing.filechooser.FileNameExtensionFilter;
import java.awt.*;
import java.awt.event.*;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.Base64;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;

import static java.lang.System.out;

public class PGPWindow2 extends JFrame {
    private static final String SHOW_GEN_PANEL = String.valueOf(0);
    private static final Insets DEFAULT_GC_INSETS = new Insets(10, 10, 10, 10);
    private static final int KEY_TYPE_PUB = 1;
    private static final int KEY_TYPE_SEC = 0;

    private static final String SHOW_MAIN_PANEL = String.valueOf(1);
    private CardLayout rootLayout;
    private JPanel rootPanel;
    private JTextField identTxt;
    private JPasswordField passwdTxt;
    private JButton genKeyBtn;
    private Thread genThread;
    private PGPKeyRingGenerator keyRing;
    private static final Path STORE_PATH = Path.of(System.getProperty("user.home"), ".archivr", "store.db");
    private JTabbedPane messengerTabs;
    private JTextArea encMsgTxt;
    private JButton loadEncKeyBtn;
    private JButton newKeyBtn;
    private Nitrite db;
    private ObjectRepository<KeyRepo> keyRepo;
    private PGPPublicKeyRing activePubRing = null;
    private JTextField pubKeyHashTxt;
    private JList<KeyRepo> pubsList;
    private JButton uploadPubKey;
    private JTextField pubKeyDateTxt;

    public PGPWindow2() throws IOException {
        super("pretty good secrets");

        initStorage();

        JPanel mainFrame = buildFrame();

        JPanel genPanel = buildGenerationPanel();

        JPanel mainPanel = buildMainPanel();

        postBuild();

        SwingUtilities.invokeLater(() -> {
            setVisible(true);
            // minimize window while testing
            //setState(JFrame.ICONIFIED);
        });

        /*SwingWorker worker1 = new SwingWorker() {
            @Override
            protected Object doInBackground() throws Exception {
                while(true) {
                    out.println("size: " + keyCollection.size());
                }
            }
        };
        worker1.execute();*/
    }

    private void postBuild() throws IOException {
        if(keyRepo.find().size() > 0) {
            rootLayout.show(rootPanel, SHOW_MAIN_PANEL);
            KeyRepo repo = setCurrentKeys();
            if(repo != null) {
                pubKeyHashTxt.setText(repo.getHash());
                pubKeyDateTxt.setText(DateTimeFormatter.ofPattern("YYYY-MM-dd HH:mm")
                        .withZone(ZoneId.systemDefault())
                        .format(Instant.ofEpochMilli(repo.getTimestamp())));
            }
        }
    }

    private KeyRepo setCurrentKeys() throws IOException {
        Cursor<KeyRepo> c = keyRepo.find();
        List<KeyRepo> res = IteratorUtils.toList(c.iterator());
        // grab latest key and set for session use
        KeyRepo latest = res.stream()
                .filter((f) -> f.getType() == KEY_TYPE_PUB).min(Collections.reverseOrder(Comparator.comparingLong(KeyRepo::getTimestamp))).orElse(null);

        /*
        so we have it handy for later (repo needs to
        be converted at this point for using the pgppubkeyring instance)
        */
        if(latest != null) {
            activePubRing = ThingPGP.decodePublicRing(latest.getKey());
        }

        return latest;
    }

    private void initStorage() throws IOException {
        if(!Files.exists(STORE_PATH)) {
            Files.createDirectories(STORE_PATH.getParent());
        }

        db = Nitrite.builder().filePath(STORE_PATH.toFile()).openOrCreate();

        keyRepo = db.getRepository(KeyRepo.class);
        keyRepo.register(new ChangeListener() {
            @Override
            public void onChange(ChangeInfo changeInfo) {
                // do stuff whenever database changes
                changeInfo.getChangedItems().forEach((c) -> out.println(c.getDocument().toString()));
            }
        });

        //keyCollection.find().forEach((r) -> out.println(r.get(JSON_HASH_NAME)));
    }

    private JPanel buildMainPanel() {
        JPanel p = new JPanel();
        p.setLayout(new BorderLayout());
        p.setLayout(new BorderLayout());

        JPanel msgP = buildMessengerPanel();
        p.add(msgP, BorderLayout.CENTER);

        rootPanel.add(p, SHOW_MAIN_PANEL);

        return p;
    }

    private JPanel buildMessengerPanel() {
        JPanel p = new JPanel(new BorderLayout());
        messengerTabs = new JTabbedPane();
        JPanel encryptP = buildEncryptPanel();
        messengerTabs.add("encrypt message", encryptP);
        JPanel decrpytP = buildDecrpytPanel();
        messengerTabs.add("decrypt message", decrpytP);
        p.add(messengerTabs, BorderLayout.CENTER);

        return p;
    }

    private JPanel buildDecrpytPanel() {
        JPanel p = new JPanel();

        GridBagLayout gb = new GridBagLayout();
        GridBagConstraints gc = new GridBagConstraints();

        return p;
    }

    private JPanel buildEncryptPanel() {
        JPanel p = new JPanel();

        GridBagLayout gb = new GridBagLayout();
        p.setLayout(gb);
        GridBagConstraints gc = new GridBagConstraints();
        gc.insets = DEFAULT_GC_INSETS;

        gc.gridx = 0;
        gc.gridy = 0;
        gc.anchor = GridBagConstraints.WEST;
        p.add(new JLabel("message"), gc);

        gc.gridx = 0;
        gc.gridy = 1;
        gc.weightx = 1;
        gc.weighty = 1;
        gc.fill = GridBagConstraints.BOTH;
        gc.anchor = GridBagConstraints.CENTER;
        encMsgTxt = new JTextArea();
        encMsgTxt.setEnabled(false);
        p.add(encMsgTxt, gc);

        gc.gridx = 0;
        gc.gridy = 2;
        gc.weightx = 1;
        gc.weighty = 0;
        gc.fill = GridBagConstraints.BOTH;
        gc.anchor = GridBagConstraints.WEST;
        JPanel pubKeyInfoPanel = buildPubKeyInfoPanel();
        p.add(pubKeyInfoPanel, gc);

        gc.gridx = 0;
        gc.gridy = 3;
        gc.weightx = 1;
        gc.weighty = 0;
        gc.fill = GridBagConstraints.HORIZONTAL;
        gc.anchor = GridBagConstraints.EAST;
        JToolBar tBar = new JToolBar();
        loadEncKeyBtn = new JButton("load key...");
        loadEncKeyBtn.addActionListener((e) -> {
            JDialog d = buildPubListDialog();
        });
        tBar.add(loadEncKeyBtn);

        newKeyBtn = new JButton("new key");
        newKeyBtn.addActionListener((e) -> {
            rootLayout.show(rootPanel, SHOW_GEN_PANEL);
        });
        tBar.add(newKeyBtn);

        JButton clearEncMsgBtn = new JButton("clear");
        clearEncMsgBtn.setEnabled(false);
        clearEncMsgBtn.addActionListener((e) -> {
            encMsgTxt.setText("");
        });
        tBar.add(clearEncMsgBtn);

        JButton genPubKeyBtn = new JButton("gen pub =)");
        genPubKeyBtn.addActionListener((e) -> {
            ((JButton) e.getSource()).setEnabled(false);
            if(activePubRing != null) {
                Path pubP = Paths.get("C:/Users/chris/Desktop/pub-dump/pub-" + Utilities.crc32(Instant.now().toEpochMilli() + ".asc"));
                if(!Files.exists(pubP)) {
                    try {
                        Files.createDirectories(pubP.getParent());
                        Files.createFile(pubP);
                    } catch (IOException ex) {
                        throw new RuntimeException(ex);
                    }
                }

                try {
                    ThingPGP.exportPublicKey(activePubRing, pubP.toFile(), true);
                } catch (IOException ex) {
                    throw new RuntimeException("failed to export public key to " + pubP + ". " + ex.getMessage());
                } finally {
                    ((JButton) e.getSource()).setEnabled(true);
                }
            }
        });
        tBar.add(genPubKeyBtn);

        p.add(tBar, gc);

        return p;
    }

    private JDialog buildPubListDialog() {
        JDialog d = new JDialog(this, true);
        d.setTitle("my encryption keys");

        GridBagLayout gb = new GridBagLayout();
        d.setLayout(gb);
        GridBagConstraints gc = new GridBagConstraints();

        gc.insets = DEFAULT_GC_INSETS;
        gc.gridx = 0;
        gc.gridy = 0;
        JLabel myPubsLbl = new JLabel("double click to select from existing public keys, or upload new one");
        d.add(myPubsLbl, gc);

        gc.gridx = 0;
        gc.gridy = 1;
        DefaultListModel<KeyRepo> model = new DefaultListModel<KeyRepo>();
        keyRepo.find(
                ObjectFilters.eq(KeyRepo.JSON_TYPE_NAME, KEY_TYPE_PUB),
                FindOptions.sort(KeyRepo.JSON_TIMESTAMP_NAME, SortOrder.Descending)
        ).forEach(model::addElement);

        pubsList = new JList<KeyRepo>(model);
        JScrollPane pubPane = new JScrollPane(pubsList);
        pubsList.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                if(e.getClickCount() == 2) {
                    // double clicked
                    int index = ((JList<?>) e.getSource()).locationToIndex(e.getPoint());
                }
            }
        });
        pubsList.setCellRenderer(new PubKeyListRenderer());
        d.add(pubPane, gc);

        gc.gridx = 0;
        gc.gridy = 2;
        uploadPubKey = new JButton("upload key");
        uploadPubKey.addActionListener((e) -> {
            JFileChooser fc = new JFileChooser();
            fc.setCurrentDirectory(STORE_PATH.getParent().getParent().toFile());
            fc.setDialogTitle("select public key file");
            fc.setDialogType(JFileChooser.OPEN_DIALOG);
            fc.addChoosableFileFilter(new FileNameExtensionFilter("OpenPGP Public Key (.asc, .gpg)", "asc", "gpg"));
            fc.showOpenDialog(d);
        });
        d.add(uploadPubKey, gc);

        d.pack();
        d.setLocationRelativeTo(this);
        d.setVisible(true);

        return d;
    }

    private JPanel buildPubKeyInfoPanel() {
        JPanel p = new JPanel();

        GridBagLayout gb = new GridBagLayout();
        p.setLayout(gb);
        GridBagConstraints gc = new GridBagConstraints();

        gc.insets = DEFAULT_GC_INSETS;
        gc.gridx = 0;
        gc.gridy = 0;
        JLabel hashLbl = new JLabel("active pub key:");
        p.add(hashLbl, gc);

        gc.gridx = 1;
        gc.gridy = 0;
        gc.weightx = 1;
        gc.fill = GridBagConstraints.HORIZONTAL;
        pubKeyHashTxt = new JTextField();
        pubKeyHashTxt.setEnabled(false);
        p.add(pubKeyHashTxt, gc);

        gc.gridx = 0;
        gc.gridy = 1;
        gc.weightx = 0;
        gc.fill = GridBagConstraints.NONE;
        JLabel dateLbl = new JLabel("date:");
        p.add(dateLbl, gc);

        gc.gridx = 1;
        gc.gridy = 1;
        gc.weightx = 1;
        gc.fill = GridBagConstraints.HORIZONTAL;
        pubKeyDateTxt = new JTextField();
        pubKeyDateTxt.setEnabled(false);
        p.add(pubKeyDateTxt, gc);

        return p;
    }

    private JPanel buildGenerationPanel() {
        JPanel p = new JPanel();

        GridBagLayout gb = new GridBagLayout();
        GridBagConstraints gc = new GridBagConstraints();
        p.setLayout(gb);

        gc.insets = DEFAULT_GC_INSETS;
        gc.gridx = 0;
        gc.gridy = 0;
        p.add(new JLabel("identity"), gc);

        gc.gridx = 1;
        gc.gridy = 0;
        gc.fill = GridBagConstraints.HORIZONTAL;
        gc.weightx = 1;
        identTxt = new JTextField();
        identTxt.addKeyListener(new IdentKeyListener());
        p.add(identTxt, gc);

        gc.gridx = 0;
        gc.gridy = 1;
        gc.weightx = 0;
        gc.fill = GridBagConstraints.NONE;
        p.add(new JLabel("password"), gc);

        gc.gridx = 1;
        gc.gridy = 1;
        gc.weightx = 1;
        gc.fill = GridBagConstraints.HORIZONTAL;
        passwdTxt = new JPasswordField();
        passwdTxt.addKeyListener(new PasswordKeyListener());
        p.add(passwdTxt, gc);

        gc.gridx = 0;
        gc.gridy = 2;
        gc.weightx = 0;
        gc.fill = GridBagConstraints.NONE;
        gc.gridwidth = 2;
        gc.anchor = GridBagConstraints.EAST;
        genKeyBtn = new JButton("generate");
        genKeyBtn.setEnabled(false);
        genKeyBtn.addActionListener(new GenKeyButtonListener());
        p.add(genKeyBtn, gc);

        rootPanel.add(p, SHOW_GEN_PANEL);


        /*if(hasKeys()) {
            rootLayout.show(rootPanel, SHOW_MAIN_PANEL);
        } else {
            rootLayout.show(rootPanel, SHOW_GEN_PANEL);
        }*/

        return p;
    }

    private JPanel buildFrame() {
        try {
            UIManager.setLookAndFeel(UIManager.getSystemLookAndFeelClassName());
        } catch (ClassNotFoundException | InstantiationException | IllegalAccessException |
                 UnsupportedLookAndFeelException e) {
            throw new RuntimeException(e);
        }

        setSize(960, 720);
        setMinimumSize(getSize());
        setResizable(true);
        setLocationByPlatform(true);
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        setLayout(new BorderLayout());
        rootPanel = new JPanel();
        rootLayout = new CardLayout();
        rootLayout.setHgap(10);
        rootLayout.setVgap(10);
        rootPanel.setLayout(rootLayout);
        add(rootPanel, BorderLayout.CENTER);

        return rootPanel;
    }

    public static void main(String[] args) throws IOException {
        Security.addProvider(new BouncyCastleProvider());

        new PGPWindow2();
    }

    private class IdentKeyListener implements KeyListener {
        @Override
        public void keyTyped(KeyEvent e) {

        }

        @Override
        public void keyPressed(KeyEvent e) {

        }

        @Override
        public void keyReleased(KeyEvent e) {
            genKeyBtn.setEnabled((passwdTxt.getPassword().length > 0 && !identTxt.getText().isEmpty()));
        }
    }

    private class PasswordKeyListener implements KeyListener {
        @Override
        public void keyTyped(KeyEvent e) {

        }

        @Override
        public void keyPressed(KeyEvent e) {

        }

        @Override
        public void keyReleased(KeyEvent e) {
            genKeyBtn.setEnabled((passwdTxt.getPassword().length > 0 && !identTxt.getText().isEmpty()));
        }
    }

    private class GenKeyButtonListener implements ActionListener {
        @Override
        public void actionPerformed(ActionEvent e) {
            genThread = new GenKeyThread();
            genThread.start();
        }
    }

    private class GenKeyThread extends Thread {
        @Override
        public void run() {
            String ident = identTxt.getText().trim();
            char[] passwd = passwdTxt.getPassword();

            out.println("starting key generation...");
            identTxt.setText("");
            passwdTxt.setText("");
            genKeyBtn.setEnabled(false);
            genKeyBtn.setText("generating...");
            try {
                keyRing = ThingPGP.generateKeyRing(ident, passwd);
            } catch (PGPException e) {
                throw new RuntimeException("generation of keyrings failed. " + e.getMessage());
            }

            out.println("key generation has completed.");
            genKeyBtn.setText("generate");
            // go back to main panel
            rootLayout.show(rootPanel, SHOW_MAIN_PANEL);

            // store new keys in DB
            try {
                storePublicKey(keyRing);
            } catch (NoSuchAlgorithmException | IOException e) {
                throw new RuntimeException(e);
            }

            try {
                genThread.join();
            } catch (InterruptedException e) {
                throw new RuntimeException(e);
            }
        }
    }

    private long storeKeys(PGPKeyRingGenerator kr) throws NoSuchAlgorithmException, IOException {
        long pubId = storePublicKey(kr);
        storeSecretKey(kr, pubId);

        return pubId;
    }

    private void storeSecretKey(PGPKeyRingGenerator kr, long pubId) throws IOException, NoSuchAlgorithmException {
        JSONObject j = new JSONObject();

        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        PGPSecretKeyRing ring = kr.generateSecretKeyRing();
        ring.encode(bos);

        byte[] hash = MessageDigest.getInstance("SHA-256").digest(bos.toByteArray());

        long ts = Instant.now().toEpochMilli();

        j.put(KeyRepo.JSON_HASH_NAME, Hex.toHexString(hash));
        j.put(KeyRepo.JSON_TYPE_NAME, KEY_TYPE_SEC);
        j.put(KeyRepo.JSON_KEY_NAME, Base64.getEncoder().encodeToString(bos.toByteArray()));
        j.put(KeyRepo.JSON_TIMESTAMP_NAME, ts);
        List<PGPSecretKey> keyList = Lists.newArrayList(ring.getSecretKeys());
        PGPSecretKey key = keyList.stream()
                .filter((k1) -> k1.getKeyID() == pubId)
                .findFirst().get();
        j.put(KeyRepo.JSON_PUBID_NAME, key.getKeyID());

        /*WriteBatch wb = db.createWriteBatch();
        wb.put(hash, bytes(j.toString()));
        wb.close();
        db.write(wb);*/

    }

    private long storePublicKey(PGPKeyRingGenerator kr) throws IOException, NoSuchAlgorithmException {
        //JSONObject j = new JSONObject();
        ByteArrayOutputStream pubBos = new ByteArrayOutputStream();
        PGPPublicKeyRing pubRing = kr.generatePublicKeyRing();
        pubRing.encode(pubBos);
        byte[] pubRingB = pubBos.toByteArray();
        byte[] pubHash = MessageDigest.getInstance("SHA-256").digest(pubBos.toByteArray());

        long ts = Instant.now().toEpochMilli();
        List<PGPPublicKey> pubList = Lists.newArrayList(pubRing.getPublicKeys());
        long pubId = pubList.stream()
                .filter(PGPPublicKey::isEncryptionKey)
                .findFirst()
                .get().getKeyID();

        KeyRepo newKey = new KeyRepo();
        newKey.setHash(Hex.toHexString(pubHash));
        newKey.setType(KEY_TYPE_PUB);
        newKey.setKey(pubRingB);
        newKey.setTimestamp(ts);
        newKey.setPubId(pubId);
        WriteResult res = keyRepo.insert(newKey);
        res.forEach((i) -> out.println(i.toString()));

        /*Document doc = Document
                .createDocument(KeyRepo.JSON_HASH_NAME, Hex.toHexString(pubHash))
                .put(KeyRepo.JSON_TYPE_NAME, KEY_TYPE_PUB)
                .put(KeyRepo.JSON_KEY_NAME, Base64.getEncoder().encodeToString(pubRingB))
                .put(KeyRepo.JSON_TIMESTAMP_NAME, ts)
                .put(KeyRepo.JSON_PUBID_NAME, pubId);
        keyCollection.insert(doc);*/

        /*j.put(JSON_HASH_NAME, Hex.toHexString(pubHash));
        j.put(JSON_TYPE_NAME, KEY_TYPE_PUB);
        j.put(JSON_KEY_NAME, Base64.getEncoder().encodeToString(pubRingB));
        j.put(JSON_TIMESTAMP_NAME, ts);

        j.put(JSON_PUBID_NAME, pubId);*/

        return pubId;
    }
}
