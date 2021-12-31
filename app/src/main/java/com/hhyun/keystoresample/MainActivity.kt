package com.hhyun.keystoresample

import android.os.Build
import androidx.appcompat.app.AppCompatActivity
import android.os.Bundle
import kotlinx.android.synthetic.main.activity_main.*

class MainActivity : AppCompatActivity() {

    private var result = ""

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        val data = tv_data.text.toString()
        result = data

        button_encrypt.setOnClickListener {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                result = EncryptManager.getEncrypted(this@MainActivity, result)
                tv_result.text = result
            }
        }

        button_decrypt.setOnClickListener {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                result = EncryptManager.getDecrypted(this@MainActivity, result)
                tv_result.text = result
            }
        }

        button_reset.setOnClickListener {
            result = data
        }

    }

}