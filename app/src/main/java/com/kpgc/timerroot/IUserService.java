/*
 * This file is auto-generated.  DO NOT MODIFY.
 */
package com.kpgc.timerroot;
public interface IUserService extends android.os.IInterface
{
  /** Default implementation for IUserService. */
  public static class Default implements com.kpgc.timerroot.IUserService
  {
    @Override public void destroy() throws android.os.RemoteException
    {
    }
    @Override public void exit() throws android.os.RemoteException
    {
    }
    @Override public java.lang.String install(java.lang.String apkPath) throws android.os.RemoteException
    {
      return null;
    }
    @Override public java.lang.String run(java.lang.String args) throws android.os.RemoteException
    {
      return null;
    }
    @Override public java.lang.String runDetached(java.lang.String args) throws android.os.RemoteException
    {
      return null;
    }
    @Override public java.lang.String readLog() throws android.os.RemoteException
    {
      return null;
    }
    @Override public java.lang.String openRoot() throws android.os.RemoteException
    {
      return null;
    }
    @Override public java.lang.String execRoot(java.lang.String cmd) throws android.os.RemoteException
    {
      return null;
    }
    @Override public java.lang.String closeRoot() throws android.os.RemoteException
    {
      return null;
    }
    @Override public java.lang.String info() throws android.os.RemoteException
    {
      return null;
    }
    @Override public java.lang.String rebootDevice() throws android.os.RemoteException
    {
      return null;
    }
    @Override
    public android.os.IBinder asBinder() {
      return null;
    }
  }
  /** Local-side IPC implementation stub class. */
  public static abstract class Stub extends android.os.Binder implements com.kpgc.timerroot.IUserService
  {
    /** Construct the stub at attach it to the interface. */
    public Stub()
    {
      this.attachInterface(this, DESCRIPTOR);
    }
    /**
     * Cast an IBinder object into an com.kpgc.timerroot.IUserService interface,
     * generating a proxy if needed.
     */
    public static com.kpgc.timerroot.IUserService asInterface(android.os.IBinder obj)
    {
      if ((obj==null)) {
        return null;
      }
      android.os.IInterface iin = obj.queryLocalInterface(DESCRIPTOR);
      if (((iin!=null)&&(iin instanceof com.kpgc.timerroot.IUserService))) {
        return ((com.kpgc.timerroot.IUserService)iin);
      }
      return new com.kpgc.timerroot.IUserService.Stub.Proxy(obj);
    }
    @Override public android.os.IBinder asBinder()
    {
      return this;
    }
    @Override public boolean onTransact(int code, android.os.Parcel data, android.os.Parcel reply, int flags) throws android.os.RemoteException
    {
      java.lang.String descriptor = DESCRIPTOR;
      if (code >= android.os.IBinder.FIRST_CALL_TRANSACTION && code <= android.os.IBinder.LAST_CALL_TRANSACTION) {
        data.enforceInterface(descriptor);
      }
      switch (code)
      {
        case INTERFACE_TRANSACTION:
        {
          reply.writeString(descriptor);
          return true;
        }
      }
      switch (code)
      {
        case TRANSACTION_destroy:
        {
          this.destroy();
          reply.writeNoException();
          break;
        }
        case TRANSACTION_exit:
        {
          this.exit();
          reply.writeNoException();
          break;
        }
        case TRANSACTION_install:
        {
          java.lang.String _arg0;
          _arg0 = data.readString();
          java.lang.String _result = this.install(_arg0);
          reply.writeNoException();
          reply.writeString(_result);
          break;
        }
        case TRANSACTION_run:
        {
          java.lang.String _arg0;
          _arg0 = data.readString();
          java.lang.String _result = this.run(_arg0);
          reply.writeNoException();
          reply.writeString(_result);
          break;
        }
        case TRANSACTION_runDetached:
        {
          java.lang.String _arg0;
          _arg0 = data.readString();
          java.lang.String _result = this.runDetached(_arg0);
          reply.writeNoException();
          reply.writeString(_result);
          break;
        }
        case TRANSACTION_readLog:
        {
          java.lang.String _result = this.readLog();
          reply.writeNoException();
          reply.writeString(_result);
          break;
        }
        case TRANSACTION_openRoot:
        {
          java.lang.String _result = this.openRoot();
          reply.writeNoException();
          reply.writeString(_result);
          break;
        }
        case TRANSACTION_execRoot:
        {
          java.lang.String _arg0;
          _arg0 = data.readString();
          java.lang.String _result = this.execRoot(_arg0);
          reply.writeNoException();
          reply.writeString(_result);
          break;
        }
        case TRANSACTION_closeRoot:
        {
          java.lang.String _result = this.closeRoot();
          reply.writeNoException();
          reply.writeString(_result);
          break;
        }
        case TRANSACTION_info:
        {
          java.lang.String _result = this.info();
          reply.writeNoException();
          reply.writeString(_result);
          break;
        }
        case TRANSACTION_rebootDevice:
        {
          java.lang.String _result = this.rebootDevice();
          reply.writeNoException();
          reply.writeString(_result);
          break;
        }
        default:
        {
          return super.onTransact(code, data, reply, flags);
        }
      }
      return true;
    }
    private static class Proxy implements com.kpgc.timerroot.IUserService
    {
      private android.os.IBinder mRemote;
      Proxy(android.os.IBinder remote)
      {
        mRemote = remote;
      }
      @Override public android.os.IBinder asBinder()
      {
        return mRemote;
      }
      public java.lang.String getInterfaceDescriptor()
      {
        return DESCRIPTOR;
      }
      @Override public void destroy() throws android.os.RemoteException
      {
        android.os.Parcel _data = android.os.Parcel.obtain();
        android.os.Parcel _reply = android.os.Parcel.obtain();
        try {
          _data.writeInterfaceToken(DESCRIPTOR);
          boolean _status = mRemote.transact(Stub.TRANSACTION_destroy, _data, _reply, 0);
          _reply.readException();
        }
        finally {
          _reply.recycle();
          _data.recycle();
        }
      }
      @Override public void exit() throws android.os.RemoteException
      {
        android.os.Parcel _data = android.os.Parcel.obtain();
        android.os.Parcel _reply = android.os.Parcel.obtain();
        try {
          _data.writeInterfaceToken(DESCRIPTOR);
          boolean _status = mRemote.transact(Stub.TRANSACTION_exit, _data, _reply, 0);
          _reply.readException();
        }
        finally {
          _reply.recycle();
          _data.recycle();
        }
      }
      @Override public java.lang.String install(java.lang.String apkPath) throws android.os.RemoteException
      {
        android.os.Parcel _data = android.os.Parcel.obtain();
        android.os.Parcel _reply = android.os.Parcel.obtain();
        java.lang.String _result;
        try {
          _data.writeInterfaceToken(DESCRIPTOR);
          _data.writeString(apkPath);
          boolean _status = mRemote.transact(Stub.TRANSACTION_install, _data, _reply, 0);
          _reply.readException();
          _result = _reply.readString();
        }
        finally {
          _reply.recycle();
          _data.recycle();
        }
        return _result;
      }
      @Override public java.lang.String run(java.lang.String args) throws android.os.RemoteException
      {
        android.os.Parcel _data = android.os.Parcel.obtain();
        android.os.Parcel _reply = android.os.Parcel.obtain();
        java.lang.String _result;
        try {
          _data.writeInterfaceToken(DESCRIPTOR);
          _data.writeString(args);
          boolean _status = mRemote.transact(Stub.TRANSACTION_run, _data, _reply, 0);
          _reply.readException();
          _result = _reply.readString();
        }
        finally {
          _reply.recycle();
          _data.recycle();
        }
        return _result;
      }
      @Override public java.lang.String runDetached(java.lang.String args) throws android.os.RemoteException
      {
        android.os.Parcel _data = android.os.Parcel.obtain();
        android.os.Parcel _reply = android.os.Parcel.obtain();
        java.lang.String _result;
        try {
          _data.writeInterfaceToken(DESCRIPTOR);
          _data.writeString(args);
          boolean _status = mRemote.transact(Stub.TRANSACTION_runDetached, _data, _reply, 0);
          _reply.readException();
          _result = _reply.readString();
        }
        finally {
          _reply.recycle();
          _data.recycle();
        }
        return _result;
      }
      @Override public java.lang.String readLog() throws android.os.RemoteException
      {
        android.os.Parcel _data = android.os.Parcel.obtain();
        android.os.Parcel _reply = android.os.Parcel.obtain();
        java.lang.String _result;
        try {
          _data.writeInterfaceToken(DESCRIPTOR);
          boolean _status = mRemote.transact(Stub.TRANSACTION_readLog, _data, _reply, 0);
          _reply.readException();
          _result = _reply.readString();
        }
        finally {
          _reply.recycle();
          _data.recycle();
        }
        return _result;
      }
      @Override public java.lang.String openRoot() throws android.os.RemoteException
      {
        android.os.Parcel _data = android.os.Parcel.obtain();
        android.os.Parcel _reply = android.os.Parcel.obtain();
        java.lang.String _result;
        try {
          _data.writeInterfaceToken(DESCRIPTOR);
          boolean _status = mRemote.transact(Stub.TRANSACTION_openRoot, _data, _reply, 0);
          _reply.readException();
          _result = _reply.readString();
        }
        finally {
          _reply.recycle();
          _data.recycle();
        }
        return _result;
      }
      @Override public java.lang.String execRoot(java.lang.String cmd) throws android.os.RemoteException
      {
        android.os.Parcel _data = android.os.Parcel.obtain();
        android.os.Parcel _reply = android.os.Parcel.obtain();
        java.lang.String _result;
        try {
          _data.writeInterfaceToken(DESCRIPTOR);
          _data.writeString(cmd);
          boolean _status = mRemote.transact(Stub.TRANSACTION_execRoot, _data, _reply, 0);
          _reply.readException();
          _result = _reply.readString();
        }
        finally {
          _reply.recycle();
          _data.recycle();
        }
        return _result;
      }
      @Override public java.lang.String closeRoot() throws android.os.RemoteException
      {
        android.os.Parcel _data = android.os.Parcel.obtain();
        android.os.Parcel _reply = android.os.Parcel.obtain();
        java.lang.String _result;
        try {
          _data.writeInterfaceToken(DESCRIPTOR);
          boolean _status = mRemote.transact(Stub.TRANSACTION_closeRoot, _data, _reply, 0);
          _reply.readException();
          _result = _reply.readString();
        }
        finally {
          _reply.recycle();
          _data.recycle();
        }
        return _result;
      }
      @Override public java.lang.String info() throws android.os.RemoteException
      {
        android.os.Parcel _data = android.os.Parcel.obtain();
        android.os.Parcel _reply = android.os.Parcel.obtain();
        java.lang.String _result;
        try {
          _data.writeInterfaceToken(DESCRIPTOR);
          boolean _status = mRemote.transact(Stub.TRANSACTION_info, _data, _reply, 0);
          _reply.readException();
          _result = _reply.readString();
        }
        finally {
          _reply.recycle();
          _data.recycle();
        }
        return _result;
      }
      @Override public java.lang.String rebootDevice() throws android.os.RemoteException
      {
        android.os.Parcel _data = android.os.Parcel.obtain();
        android.os.Parcel _reply = android.os.Parcel.obtain();
        java.lang.String _result;
        try {
          _data.writeInterfaceToken(DESCRIPTOR);
          boolean _status = mRemote.transact(Stub.TRANSACTION_rebootDevice, _data, _reply, 0);
          _reply.readException();
          _result = _reply.readString();
        }
        finally {
          _reply.recycle();
          _data.recycle();
        }
        return _result;
      }
    }
    static final int TRANSACTION_destroy = (android.os.IBinder.FIRST_CALL_TRANSACTION + 16777114);
    static final int TRANSACTION_exit = (android.os.IBinder.FIRST_CALL_TRANSACTION + 1);
    static final int TRANSACTION_install = (android.os.IBinder.FIRST_CALL_TRANSACTION + 2);
    static final int TRANSACTION_run = (android.os.IBinder.FIRST_CALL_TRANSACTION + 3);
    static final int TRANSACTION_runDetached = (android.os.IBinder.FIRST_CALL_TRANSACTION + 4);
    static final int TRANSACTION_readLog = (android.os.IBinder.FIRST_CALL_TRANSACTION + 5);
    static final int TRANSACTION_openRoot = (android.os.IBinder.FIRST_CALL_TRANSACTION + 6);
    static final int TRANSACTION_execRoot = (android.os.IBinder.FIRST_CALL_TRANSACTION + 7);
    static final int TRANSACTION_closeRoot = (android.os.IBinder.FIRST_CALL_TRANSACTION + 8);
    static final int TRANSACTION_info = (android.os.IBinder.FIRST_CALL_TRANSACTION + 9);
    static final int TRANSACTION_rebootDevice = (android.os.IBinder.FIRST_CALL_TRANSACTION + 10);
  }
  public static final java.lang.String DESCRIPTOR = "com.kpgc.timerroot.IUserService";
  public void destroy() throws android.os.RemoteException;
  public void exit() throws android.os.RemoteException;
  public java.lang.String install(java.lang.String apkPath) throws android.os.RemoteException;
  public java.lang.String run(java.lang.String args) throws android.os.RemoteException;
  public java.lang.String runDetached(java.lang.String args) throws android.os.RemoteException;
  public java.lang.String readLog() throws android.os.RemoteException;
  public java.lang.String openRoot() throws android.os.RemoteException;
  public java.lang.String execRoot(java.lang.String cmd) throws android.os.RemoteException;
  public java.lang.String closeRoot() throws android.os.RemoteException;
  public java.lang.String info() throws android.os.RemoteException;
  public java.lang.String rebootDevice() throws android.os.RemoteException;
}
