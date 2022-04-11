package com.kanxue.secondshell_80;

import androidx.appcompat.app.AppCompatActivity;

import android.content.Context;
import android.os.Bundle;
import android.widget.TextView;

import java.io.File;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;

import dalvik.system.DexClassLoader;

public class MainActivity extends AppCompatActivity {

    // Used to load the 'native-lib' library on application startup.
    static {
        System.loadLibrary("native-lib");
    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        // Example of a call to a native method
        TextView tv = findViewById(R.id.sample_text);
        tv.setText(stringFromJNI());
        SecondShell();
        testDexClassLoader(this,"/sdcard/4_chouqu.dex");
    }
    // public native String stringFromJNI();
    public void testDexClassLoader(Context context, String dexfilepath){

        File optfile=context.getDir("opt_dex",0);
        File libfile=context.getDir("lib_path",0);
        ClassLoader parentClassloader=MainActivity.class.getClassLoader();
        ClassLoader tmpClassLoader=context.getClassLoader();
        DexClassLoader dexClassLoader=new DexClassLoader(dexfilepath,optfile.getAbsolutePath(),libfile.getAbsolutePath(),MainActivity.class.getClassLoader());
        Class<?> clazz=null;
        try {
            clazz = dexClassLoader.loadClass("com.kanxue.test02.TestClass");
        } catch (ClassNotFoundException e) {
            e.printStackTrace();
        }
        if(clazz!=null){
            try {
                Method testFuncMethod=clazz.getDeclaredMethod("testFunc");
                Object obj=clazz.newInstance();
                testFuncMethod.invoke(obj);
            } catch (NoSuchMethodException e) {
                e.printStackTrace();
            } catch (IllegalAccessException e) {
                e.printStackTrace();
            } catch (InstantiationException e) {
                e.printStackTrace();
            } catch (InvocationTargetException e) {
                e.printStackTrace();
            }
        }


    }
    /**
     * A native method that is implemented by the 'native-lib' native library,
     * which is packaged with this application.
     */
    public native String stringFromJNI();
    public native void SecondShell();
}
