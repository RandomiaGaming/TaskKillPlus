using System;
using System.Diagnostics;
using System.Management;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;

namespace TaskKillPlus
{
	public static class Program
	{
		public static void Main(string[] args)
		{
			ProcessInfo[] processInfo = EnumProcesses();
			foreach (ProcessInfo process in processInfo)
			{
				if (process.MMFP.Contains("wininit"))
				{
					ForceKillProcess(process.PID);
					break;
				}
			}
			Console.ReadLine();
		}
		#region EnumPIDs
		[DllImport("psapi.dll", SetLastError = true)]
		private static extern bool EnumProcesses([MarshalAs(UnmanagedType.LPArray, ArraySubType = UnmanagedType.U4)][In][Out] uint[] processIds, uint arraySizeBytes, [MarshalAs(UnmanagedType.U4)] out uint bytesCopied);
		public static IntPtr[] EnumPIDs(uint maxProcesses = 4096)
		{
			uint[] processIds = new uint[maxProcesses];
			if (!EnumProcesses(processIds, 4096 * sizeof(uint), out uint bytesReturned))
			{
				throw new Exception("Failed to enumerate processes.");
			}
			uint processCount = bytesReturned / sizeof(uint);
			IntPtr[] result = new IntPtr[processCount];
			for (int i = 0; i < processCount; i++)
			{
				result[i] = (IntPtr)processIds[i];
			}
			return result;
		}
		#endregion
		#region QueryMMFP
		[DllImport("kernel32.dll", SetLastError = true)]
		private static extern IntPtr OpenProcess(int dwDesiredAccess, bool bInheritHandle, int dwProcessId);
		[DllImport("kernel32.dll", SetLastError = true)]
		[return: MarshalAs(UnmanagedType.Bool)]
		private static extern bool QueryFullProcessImageName(IntPtr hProcess, int dwFlags, StringBuilder lpExeName, ref int lpdwSize);
		[DllImport("kernel32.dll")]
		[return: MarshalAs(UnmanagedType.Bool)]
		private static extern bool CloseHandle(IntPtr hObject);
		private const int PROCESS_QUERY_LIMITED_INFORMATION = 0x1000;
		private const int PROCESS_VM_READ = 0x0010;
		public static string QueryMMFP(IntPtr PID, uint maxMMFPLength = 4096)
		{
			IntPtr hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, false, PID.ToInt32());
			if (hProcess == IntPtr.Zero)
			{
				throw new Exception($"Failed to open process with PID {PID}");
			}
			try
			{
				StringBuilder exePath = new StringBuilder((int)maxMMFPLength);
				int bufferSize = exePath.Capacity;
				if (QueryFullProcessImageName(hProcess, 0, exePath, ref bufferSize))
				{
					return exePath.ToString();
				}
				else
				{
					throw new Exception($"Failed to retrieve the process image path. Error code: {Marshal.GetLastWin32Error()}");
				}
			}
			finally
			{
				CloseHandle(hProcess);
			}
		}
		#endregion
		#region GetEPwithWMI
		public static string GetEPwithWMI(IntPtr PID)
		{
			ObjectQuery query = new ObjectQuery($"SELECT * FROM Win32_Process WHERE ProcessId = {PID}");
			ManagementObjectSearcher searcher = new ManagementObjectSearcher(query);
			ManagementObjectCollection processCollection = searcher.Get();
			foreach (ManagementObject process in processCollection)
			{
				string output = process["ExecutablePath"]?.ToString();
				if (output is null)
				{
					throw new Exception($"WMI returned null when queried for ExecutablePath on PID {PID}.");
				}
				return output;
			}
			throw new Exception($"WMI could not find process with ID {PID}.");
		}
		#endregion
		#region EnumProcesses
		public static ProcessInfo[] EnumProcesses()
		{
			IntPtr[] PIDs = EnumPIDs();
			ProcessInfo[] output = new ProcessInfo[PIDs.Length];
			for (int i = 0; i < PIDs.Length; i++)
			{
				try
				{
					output[i] = new ProcessInfo() { PID = PIDs[i], MMFP = QueryMMFP(PIDs[i]) };
				}
				catch
				{
					try
					{
						output[i] = new ProcessInfo() { PID = PIDs[i], MMFP = GetEPwithWMI(PIDs[i]) };
					}
					catch
					{
						output[i] = new ProcessInfo() { PID = PIDs[i], MMFP = "Not Found" };
					}
				}
			}
			return output;
		}
		public struct ProcessInfo
		{
			public IntPtr PID;
			public string MMFP;
		}
		#endregion
		#region FlagCritical
		using System;
using System.Runtime.InteropServices;

class Program
	{
		private const int PROCESS_CREATE_PROCESS = 0x0080;
		private const int PROCESS_CREATE_THREAD = 0x0002;
		private const int PROCESS_QUERY_INFORMATION = 0x0400;
		private const int PROCESS_VM_OPERATION = 0x0008;
		private const int PROCESS_VM_WRITE = 0x0020;
		private const int PROCESS_VM_READ = 0x0010;

		private const uint SE_PRIVILEGE_ENABLED = 0x00000002;
		private const string SE_DEBUG_NAME = "SeDebugPrivilege";

		[DllImport("kernel32.dll")]
		private static extern IntPtr GetCurrentProcess();

		[DllImport("advapi32.dll", SetLastError = true)]
		[return: MarshalAs(UnmanagedType.Bool)]
		private static extern bool OpenProcessToken(IntPtr processHandle, uint desiredAccess, out IntPtr tokenHandle);

		[DllImport("kernel32.dll")]
		private static extern IntPtr OpenThread(uint dwDesiredAccess, bool bInheritHandle, uint dwThreadId);

		[DllImport("kernel32.dll")]
		private static extern int SuspendThread(IntPtr hThread);

		[DllImport("kernel32.dll")]
		private static extern int ResumeThread(IntPtr hThread);

		[DllImport("kernel32.dll", SetLastError = true)]
		[return: MarshalAs(UnmanagedType.Bool)]
		private static extern bool CloseHandle(IntPtr hObject);

		[DllImport("advapi32.dll", SetLastError = true)]
		[return: MarshalAs(UnmanagedType.Bool)]
		private static extern bool AdjustTokenPrivileges(IntPtr tokenHandle, [MarshalAs(UnmanagedType.Bool)] bool disableAllPrivileges, ref TOKEN_PRIVILEGES newState, uint bufferLength, IntPtr previoudState, IntPtr returnLength);

		[StructLayout(LayoutKind.Sequential)]
		private struct TOKEN_PRIVILEGES
		{
			public uint PrivilegeCount;
			public LUID Luid;
			public uint Attributes;
		}

		[StructLayout(LayoutKind.Sequential)]
		private struct LUID
		{
			public uint LowPart;
			public int HighPart;
		}

		[DllImport("ntdll.dll", SetLastError = true)]
		private static extern int NtSetInformationProcess(IntPtr processHandle, int processInformationClass, ref int processInformation, int processInformationLength);

		private const int ProcessBreakOnTermination = 29;

		public static void SetCriticalProcess(int pid)
		{
			IntPtr processHandle = OpenProcess(ProcessAccessFlags.All, false, pid);
			if (processHandle == IntPtr.Zero)
			{
				Console.WriteLine($"Failed to open process with PID {pid}");
				return;
			}

			IntPtr tokenHandle;
			if (!OpenProcessToken(processHandle, 0x28, out tokenHandle)) // TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY
			{
				Console.WriteLine("Failed to open process token");
				CloseHandle(processHandle);
				return;
			}

			TOKEN_PRIVILEGES tp;
			tp.PrivilegeCount = 1;
			tp.Luid = new LUID();
			tp.Attributes = SE_PRIVILEGE_ENABLED;

			if (!LookupPrivilegeValue(null, SE_DEBUG_NAME, out tp.Luid))
			{
				Console.WriteLine("Failed to lookup privilege value");
				CloseHandle(processHandle);
				CloseHandle(tokenHandle);
				return;
			}

			if (!AdjustTokenPrivileges(tokenHandle, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero))
			{
				Console.WriteLine("Failed to adjust token privileges");
				CloseHandle(processHandle);
				CloseHandle(tokenHandle);
				return;
			}

			int breakOnTermination = 1;
			if (NtSetInformationProcess(processHandle, ProcessBreakOnTermination, ref breakOnTermination, sizeof(int)) != 0)
			{
				Console.WriteLine("Failed to set process as critical");
				CloseHandle(processHandle);
				CloseHandle(tokenHandle);
				return;
			}

			Console.WriteLine($"Process with PID {pid} is now critical.");
			CloseHandle(processHandle);
			CloseHandle(tokenHandle);
		}

		public static void RevokeCriticalProcess(int pid)
		{
			IntPtr processHandle = OpenProcess(ProcessAccessFlags.All, false, pid);
			if (processHandle == IntPtr.Zero)
			{
				Console.WriteLine($"Failed to open process with PID {pid}");
				return;
			}

			int breakOnTermination = 0;
			if (NtSetInformationProcess(processHandle, ProcessBreakOnTermination, ref breakOnTermination, sizeof(int)) != 0)
			{
				Console.WriteLine("Failed to revoke process critical status");
				CloseHandle(processHandle);
				return;
			}

			Console.WriteLine($"Process with PID {pid} is no longer critical.");
			CloseHandle(processHandle);
		}

		[Flags]
		private enum ProcessAccessFlags : uint
		{
			All = 0x001F0FFF
		}

		[DllImport("advapi32.dll", SetLastError = true)]
		[return: MarshalAs(UnmanagedType.Bool)]
		private static extern bool LookupPrivilegeValue(string lpSystemName, string lpName, out LUID lpLuid);
	}
	#endregion


	public static void ForceKillProcess(IntPtr PID)
		{
			int id = (int)PID;
			Console.WriteLine(id);
		}
	}
}
