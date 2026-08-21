package top.niunaijun.blackboxa.data

import androidx.lifecycle.MutableLiveData
import top.niunaijun.blackbox.BlackBoxCore
import top.niunaijun.blackboxa.R
import top.niunaijun.blackboxa.app.AppManager
import top.niunaijun.blackboxa.bean.GmsBean
import top.niunaijun.blackboxa.bean.GmsInstallBean
import top.niunaijun.blackboxa.util.getString


class GmsRepository {


    fun getGmsInstalledList(mInstalledLiveData: MutableLiveData<List<GmsBean>>) {
        try {
            val userList = arrayListOf<GmsBean>()

            val users = BlackBoxCore.get().users
            if (users == null || users.isEmpty()) {
                // No users yet, create default user 0
                val defaultBean = GmsBean(0, "User 0", false)
                userList.add(defaultBean)
                mInstalledLiveData.postValue(userList)
                return
            }

            users.forEach {
                try {
                    val userId = it.id
                    val userName =
                        AppManager.mRemarkSharedPreferences.getString("Remark$userId", "User $userId") ?: "User $userId"
                    val isInstalled = try {
                        BlackBoxCore.get().isInstallGms(userId)
                    } catch (e: Exception) {
                        false
                    }
                    val bean = GmsBean(userId, userName, isInstalled)
                    userList.add(bean)
                } catch (e: Exception) {
                    android.util.Log.e("GmsRepository", "Error processing user: ${e.message}")
                }
            }

            mInstalledLiveData.postValue(userList)
        } catch (e: Exception) {
            android.util.Log.e("GmsRepository", "Error getting GMS list: ${e.message}")
            // Post empty list with default user so UI shows something
            val fallback = arrayListOf(GmsBean(0, "User 0", false))
            mInstalledLiveData.postValue(fallback)
        }
    }

    fun installGms(
        userID: Int,
        mUpdateInstalledLiveData: MutableLiveData<GmsInstallBean>
    ) {
        try {
            val installResult = BlackBoxCore.get().installGms(userID)

            val result = if (installResult.success) {
                getString(R.string.install_success)
            } else {
                getString(R.string.install_fail, installResult.msg ?: "Unknown error")
            }

            val bean = GmsInstallBean(userID, installResult.success, result)
            mUpdateInstalledLiveData.postValue(bean)
        } catch (e: Exception) {
            android.util.Log.e("GmsRepository", "Error installing GMS: ${e.message}")
            val bean = GmsInstallBean(userID, false, "Install failed: ${e.message}")
            mUpdateInstalledLiveData.postValue(bean)
        }
    }

    fun uninstallGms(
        userID: Int,
        mUpdateInstalledLiveData: MutableLiveData<GmsInstallBean>
    ) {
        try {
            var isSuccess = false
            if (BlackBoxCore.get().isInstallGms(userID)) {
                isSuccess = BlackBoxCore.get().uninstallGms(userID)
            }

            val result = if (isSuccess) {
                getString(R.string.uninstall_success)
            } else {
                getString(R.string.uninstall_fail)
            }

            val bean = GmsInstallBean(userID, isSuccess, result)
            mUpdateInstalledLiveData.postValue(bean)
        } catch (e: Exception) {
            android.util.Log.e("GmsRepository", "Error uninstalling GMS: ${e.message}")
            val bean = GmsInstallBean(userID, false, "Uninstall failed: ${e.message}")
            mUpdateInstalledLiveData.postValue(bean)
        }
    }
}