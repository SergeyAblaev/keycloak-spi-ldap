package com.scontrol.auth.provider.user;

import org.keycloak.component.ComponentModel;
//import org.keycloak.storage.CacheableStorageProviderModel;
import org.keycloak.storage.UserStorageProvider;

public class CimpUserStorageProviderModel extends ComponentModel {
//public class CimpUserStorageProviderModel extends CacheableStorageProviderModel {
//    public static final String IMPORT_ENABLED = "importEnabled";
//    public static final String FULL_SYNC_PERIOD = "fullSyncPeriod";
//    public static final String CHANGED_SYNC_PERIOD = "changedSyncPeriod";
//    public static final String LAST_SYNC = "lastSync";
//    private transient Integer fullSyncPeriod;
//    private transient Integer changedSyncPeriod;
//    private transient Integer lastSync;
    private transient Boolean importEnabled;

    public CimpUserStorageProviderModel() {
        this.setProviderType(UserStorageProvider.class.getName());
    }

    public CimpUserStorageProviderModel(ComponentModel copy) {
        super(copy);
    }

    public boolean isImportEnabled() {
        if (this.importEnabled == null) {
            String val = (String)this.getConfig().getFirst("importEnabled");
            if (val == null) {
                this.importEnabled = true;
            } else {
                this.importEnabled = Boolean.valueOf(val);
            }
        }

        return this.importEnabled;
    }

    public void setImportEnabled(boolean flag) {
        this.importEnabled = flag;
        this.getConfig().putSingle("importEnabled", Boolean.toString(flag));
    }
//
//    public int getFullSyncPeriod() {
//        if (this.fullSyncPeriod == null) {
//            String val = (String)this.getConfig().getFirst("fullSyncPeriod");
//            if (val == null) {
//                this.fullSyncPeriod = -1;
//            } else {
//                this.fullSyncPeriod = Integer.valueOf(val);
//            }
//        }
//
//        return this.fullSyncPeriod;
//    }
//
//    public void setFullSyncPeriod(int fullSyncPeriod) {
//        this.fullSyncPeriod = fullSyncPeriod;
//        this.getConfig().putSingle("fullSyncPeriod", Integer.toString(fullSyncPeriod));
//    }
//
//    public int getChangedSyncPeriod() {
//        if (this.changedSyncPeriod == null) {
//            String val = (String)this.getConfig().getFirst("changedSyncPeriod");
//            if (val == null) {
//                this.changedSyncPeriod = -1;
//            } else {
//                this.changedSyncPeriod = Integer.valueOf(val);
//            }
//        }
//
//        return this.changedSyncPeriod;
//    }
//
//    public void setChangedSyncPeriod(int changedSyncPeriod) {
//        this.changedSyncPeriod = changedSyncPeriod;
//        this.getConfig().putSingle("changedSyncPeriod", Integer.toString(changedSyncPeriod));
//    }
//
//    public int getLastSync() {
//        if (this.lastSync == null) {
//            String val = (String)this.getConfig().getFirst("lastSync");
//            if (val == null) {
//                this.lastSync = 0;
//            } else {
//                this.lastSync = Integer.valueOf(val);
//            }
//        }
//
//        return this.lastSync;
//    }
//
//    public void setLastSync(int lastSync) {
//        this.lastSync = lastSync;
//        this.getConfig().putSingle("lastSync", Integer.toString(lastSync));
//    }
}
